--
-- SQL functions for NIPAP
--

--
-- calc_indent is an internal function that calculates the correct indentation
-- for a prefix. It is called from a trigger function on the ip_net_plan table.
--
CREATE OR REPLACE FUNCTION calc_indent(arg_vrf integer, arg_prefix inet, delta integer) RETURNS bool AS $_$
DECLARE
	r record;
	current_indent integer;
BEGIN
	current_indent := (
		SELECT COUNT(*)
		FROM
			(SELECT DISTINCT inp.prefix
			FROM ip_net_plan inp
			WHERE vrf_id = arg_vrf
				AND iprange(prefix) >> iprange(arg_prefix::cidr)
			) AS a
		);

	UPDATE ip_net_plan SET indent = current_indent WHERE vrf_id = arg_vrf AND prefix = arg_prefix;
	UPDATE ip_net_plan SET indent = indent + delta WHERE vrf_id = arg_vrf AND iprange(prefix) << iprange(arg_prefix::cidr);

	RETURN true;
END;
$_$ LANGUAGE plpgsql;


--
-- Remove duplicate elements from an array
--
CREATE OR REPLACE FUNCTION array_undup(ANYARRAY) RETURNS ANYARRAY AS $_$
	SELECT ARRAY(
		SELECT DISTINCT $1[i]
		FROM generate_series(
			array_lower($1,1),
			array_upper($1,1)
			) AS i
		);
$_$ LANGUAGE SQL;


--
-- calc_tags is an internal function that calculates the inherited_tags
-- from parent prefixes to its children. It is called from a trigger function
-- on the ip_net_plan table.
--
CREATE OR REPLACE FUNCTION calc_tags(arg_vrf integer, arg_prefix inet) RETURNS bool AS $_$
DECLARE
	i_indent integer;
	new_inherited_tags text[];
BEGIN
	-- TODO: why don't we take the prefix as argument? That way we could save
	--		 in these selects fetching data from the table that we already have.
	i_indent := (
		SELECT indent+1
		FROM ip_net_plan
		WHERE vrf_id = arg_vrf
			AND prefix = arg_prefix
		);
	-- set default if we don't have a parent prefix
	IF i_indent IS NULL THEN
		i_indent := 0;
	END IF;

	new_inherited_tags := (
		SELECT array_undup(array_cat(inherited_tags, tags))
		FROM ip_net_plan
		WHERE vrf_id = arg_vrf
			AND prefix = arg_prefix
		);
	-- set default if we don't have a parent prefix
	IF new_inherited_tags IS NULL THEN
		new_inherited_tags := '{}';
	END IF;

	-- TODO: we don't need to update if our old tags are the same as our new
	-- TODO: we could add WHERE inherited_tags != new_inherited_tags which
	--		 could potentially speed up this update considerably, especially
	--		 with a GiN index on that column
	UPDATE ip_net_plan SET inherited_tags = new_inherited_tags WHERE vrf_id = arg_vrf AND iprange(prefix) << iprange(arg_prefix::cidr) AND indent = i_indent;

	RETURN true;
END;
$_$ LANGUAGE plpgsql;



--
-- find free IP ranges within the specified prefix
--------------------------------------------------

--
-- overloaded funciton for feeding array of IDs
--
CREATE OR REPLACE FUNCTION find_free_ranges (IN arg_prefix_ids integer[]) RETURNS SETOF iprange AS $_$
DECLARE
	id int;
	r iprange;
BEGIN
	FOR id IN (SELECT arg_prefix_ids[i] FROM generate_subscripts(arg_prefix_ids, 1) AS i) LOOP
		FOR r IN (SELECT find_free_ranges(id)) LOOP
			RETURN NEXT r;
		END LOOP;
	END LOOP;

	RETURN;
END;
$_$ LANGUAGE plpgsql;

--
-- Each range starts on the first non-used address, ie broadcast of "previous
-- prefix" + 1 and ends on address before network address of "next prefix".
--
CREATE OR REPLACE FUNCTION find_free_ranges (arg_prefix_id integer) RETURNS SETOF iprange AS $_$
DECLARE
	arg_prefix record;
	current_prefix record; -- current prefix
	max_prefix_len integer;
	last_used inet;
BEGIN
	SELECT * INTO arg_prefix FROM ip_net_plan WHERE id = arg_prefix_id;

	IF family(arg_prefix.prefix) = 4 THEN
		max_prefix_len := 32;
	ELSE
		max_prefix_len := 128;
	END IF;

	-- used the network address of the "parent" prefix as start value
	last_used := host(network(arg_prefix.prefix));

	-- loop over direct childrens of arg_prefix
	FOR current_prefix IN (SELECT * FROM ip_net_plan WHERE prefix <<= arg_prefix.prefix AND vrf_id = arg_prefix.vrf_id AND indent = arg_prefix.indent + 1 ORDER BY prefix ASC) LOOP
		-- if network address of current prefix is higher than the last used
		-- address (typically the broadcast address of the previous network) it
		-- means that this and the previous network are not adjacent, ie we
		-- have found a free range, let's return it!
		IF set_masklen(last_used, max_prefix_len)::cidr < set_masklen(current_prefix.prefix, max_prefix_len)::cidr THEN
			RETURN NEXT iprange(last_used::ipaddress, host(network(current_prefix.prefix)-1)::ipaddress);
		END IF;

		-- store current_prefix as last_used for next round
		-- if the current prefix has the max prefix length, the next free address is current_prefix + 1
		IF masklen(current_prefix.prefix) = max_prefix_len THEN
			last_used := current_prefix.prefix + 1;
		-- if broadcast of current prefix is same as the broadcast of
		-- arg_prefix we use that address as the last used, as it's really the max
		ELSIF set_masklen(broadcast(current_prefix.prefix), max_prefix_len) = set_masklen(broadcast(arg_prefix.prefix), max_prefix_len) THEN
			last_used := broadcast(current_prefix.prefix);
		-- default to using broadcast of current_prefix +1
		ELSE
			last_used := broadcast(current_prefix.prefix) + 1;
		END IF;
	END LOOP;

	-- and get the "last free" range if there is one
	IF last_used::ipaddress < set_masklen(broadcast(arg_prefix.prefix), max_prefix_len)::ipaddress THEN
		RETURN NEXT iprange(last_used::ipaddress, set_masklen(broadcast(arg_prefix.prefix), max_prefix_len)::ipaddress);
	END IF;

	RETURN;
END;
$_$ LANGUAGE plpgsql;



--
-- Return aggregated CIDRs based on ip ranges.
--
CREATE OR REPLACE FUNCTION iprange2cidr (IN arg_ipranges iprange[]) RETURNS SETOF cidr AS $_$
DECLARE
	current_range iprange;
	delta numeric(40);
	biggest integer;
	big_prefix iprange;
	rest iprange[]; -- the rest
	free_prefixes cidr[];
	max_prefix_len integer;
	p cidr;
	len integer;
BEGIN
	FOR current_range IN (SELECT arg_ipranges[s] FROM generate_series(1, array_upper(arg_ipranges, 1)) AS s) LOOP
		IF max_prefix_len IS NULL THEN
			IF family(current_range) = 4 THEN
				max_prefix_len := 32;
			ELSE
				max_prefix_len := 128;
			END IF;
		ELSE
			IF (family(current_range) = 4 AND max_prefix_len != 32) OR (family(current_range) = 6 AND max_prefix_len != 128) THEN
				RAISE EXCEPTION 'Search prefixes of inconsistent address-family provided';
			END IF;
		END IF;
	END LOOP;

	FOR current_range IN (SELECT arg_ipranges[s] FROM generate_series(1, array_upper(arg_ipranges, 1)) AS s) LOOP
		-- range is an exact CIDR
		IF current_range::cidr::iprange = current_range THEN
			RETURN NEXT current_range;
			CONTINUE;
		END IF;

		-- get size of network
		delta := upper(current_range) - lower(current_range);
		-- the inverse of 2^x to find largest bit size that fits in this prefix
		biggest := max_prefix_len - floor(log(delta)/log(2));

		-- TODO: benchmark this against an approach that uses set_masklen(lower(current_range)+delta, biggest)
		--FOR len IN (SELECT * FROM generate_series(biggest, max_prefix_len)) LOOP
		--	big_prefix := set_masklen(lower(current_range)::cidr+delta, len);
		--	IF lower(big_prefix) >= lower(current_range) AND upper(big_prefix) <= upper(current_range) THEN
		--		EXIT;
		--	END IF;
		--END LOOP;
		<<potential>>
		FOR len IN (SELECT * FROM generate_series(biggest, max_prefix_len)) LOOP
			big_prefix := set_masklen(lower(current_range)::cidr, len);
			WHILE true LOOP
				IF lower(big_prefix) >= lower(current_range) AND upper(big_prefix) <= upper(current_range) THEN
					EXIT potential;
				END IF;
				big_prefix := set_masklen(broadcast(set_masklen(lower(current_range)::cidr, len))+1, len);
				EXIT WHEN upper(big_prefix) >= upper(current_range);
			END LOOP;
		END LOOP potential;

		-- call ourself recursively with the rest between start of range and the big prefix
		IF lower(big_prefix) > lower(current_range) THEN
			FOR p IN (SELECT * FROM iprange2cidr(ARRAY[ iprange(lower(current_range), lower(big_prefix)-1) ])) LOOP
				RETURN NEXT p;
			END LOOP;
		END IF;
		-- biggest prefix
		RETURN NEXT big_prefix;
		-- call ourself recursively with the rest between end of the big prefix and the end of range
		IF upper(big_prefix) < upper(current_range) THEN
			FOR p IN (SELECT * FROM iprange2cidr(ARRAY[ iprange(upper(big_prefix)+1, upper(current_range)) ])) LOOP
				RETURN NEXT p;
			END LOOP;
		END IF;

	END LOOP;

	RETURN;
END;
$_$ LANGUAGE plpgsql;


--
-- Calculate number of free prefixes in a pool
--
CREATE OR REPLACE FUNCTION calc_pool_free_prefixes(arg_pool_id integer, arg_family integer, arg_new_prefix cidr DEFAULT NULL) RETURNS numeric(40) AS $_$
DECLARE
	pool ip_net_pool;
BEGIN
	SELECT * INTO pool FROM ip_net_pool WHERE id = arg_pool_id;
	RETURN calc_pool_free_prefixes(pool, arg_family, arg_new_prefix);
END;
$_$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION calc_pool_free_prefixes(arg_pool ip_net_pool, arg_family integer, arg_new_prefix cidr DEFAULT NULL) RETURNS numeric(40) AS $_$
DECLARE
	default_prefix_length integer;
	prefix_ids integer[];
BEGIN
	IF arg_family = 4 THEN
		default_prefix_length := arg_pool.ipv4_default_prefix_length;
	ELSE
		default_prefix_length := arg_pool.ipv6_default_prefix_length;
	END IF;

	-- not possible to determine amount of free addresses if the default prefix
	-- length is not set
	IF default_prefix_length IS NULL THEN
		RETURN NULL;
	END IF;

	-- if we don't have any member prefixes, free prefixes will be NULL
	prefix_ids := ARRAY((SELECT id FROM ip_net_plan WHERE pool_id = arg_pool.id AND family(prefix)=arg_family));
	IF array_length(prefix_ids, 1) IS NULL THEN
		RETURN NULL;
	END IF;

	RETURN cidr_count(ARRAY((SELECT iprange2cidr(ARRAY((SELECT find_free_ranges(prefix_ids)))))), default_prefix_length);
END;
$_$ LANGUAGE plpgsql;



--
-- Count the number of prefixes of a certain size that fits in the list of
-- CIDRs
--
-- Example:
--   SELECT cidr_count('{1.0.0.0/24,2.0.0.0/23}', 29);
--    cidr_count
--   ------------
--           384
--
CREATE OR REPLACE FUNCTION cidr_count(IN arg_cidrs cidr[], arg_prefix_length integer) RETURNS numeric(40) AS $_$
DECLARE
	i_family integer;
	max_prefix_len integer;
	num_cidrs numeric(40);
	p record;
	i int;
BEGIN
	num_cidrs := 0;

	-- make sure all provided search_prefixes are of same family
	FOR i IN SELECT generate_subscripts(arg_cidrs, 1) LOOP
		IF i_family IS NULL THEN
			i_family := family(arg_cidrs[i]);
		END IF;

		IF i_family != family(arg_cidrs[i]) THEN
			RAISE EXCEPTION 'Search prefixes of inconsistent address-family provided';
		END IF;
	END LOOP;

	-- determine maximum prefix-length for our family
	IF i_family = 4 THEN
		max_prefix_len := 32;
	ELSE
		max_prefix_len := 128;
	END IF;

	FOR i IN (SELECT masklen(arg_cidrs[s]) FROM generate_subscripts(arg_cidrs, 1) AS s) LOOP
		num_cidrs = num_cidrs + power(2::numeric(40), (arg_prefix_length - i));
	END LOOP;

	RETURN num_cidrs;
END;
$_$ LANGUAGE plpgsql;




--
-- find_free_prefix finds one or more prefix(es) of a certain prefix-length
-- inside a larger prefix. It is typically called by get_prefix or to return a
-- list of unused prefixes.
--

-- default to 1 prefix if no count is specified
CREATE OR REPLACE FUNCTION find_free_prefix(arg_vrf integer, IN arg_prefixes inet[], arg_wanted_prefix_len integer) RETURNS SETOF inet AS $_$
BEGIN
	RETURN QUERY SELECT * FROM find_free_prefix(arg_vrf, arg_prefixes, arg_wanted_prefix_len, 1) AS prefix;
END;
$_$ LANGUAGE plpgsql;

-- full function
CREATE OR REPLACE FUNCTION find_free_prefix(
    arg_vrf integer,
    IN arg_prefixes inet[],
    arg_wanted_prefix_len integer,
    arg_count integer
) RETURNS SETOF inet AS $_$
DECLARE
    i_family integer;
    p int;
    search_prefix inet;
    prefix_id integer;
    free_ranges iprange[];
    free_cidrs  cidr[];
    -- collection of results
    seen_prefixes cidr[] := '{}';     -- for final deduplication
    exact_entries  text[] := '{}';    -- "prefix|0"
    subnet_entries  text[] := '{}';    -- "subnet_cidr|waste" (subnet > wanted)
    candidate cidr;
    subnet_cidr cidr;
    generated inet;
    max_prefix_len integer;
    wanted_size numeric;              -- 2^(max - wanted) only for waste calculus
    waste numeric;
    entry  record;
    entryb record;
    i_found int := 0;
BEGIN
    -- sanity checking
    -- make sure all provided search_prefixes are of same family
    FOR p IN SELECT generate_subscripts(arg_prefixes, 1) LOOP
        IF i_family IS NULL THEN
            i_family := family(arg_prefixes[p]);
        ELSIF i_family != family(arg_prefixes[p]) THEN
            RAISE EXCEPTION 'Search prefixes of inconsistent address-family provided';
        END IF;
    END LOOP;

    max_prefix_len := CASE WHEN i_family = 4 THEN 32 ELSE 128 END;
    IF arg_wanted_prefix_len > max_prefix_len THEN
        RAISE EXCEPTION 'Requested prefix-length exceeds max prefix-length %', max_prefix_len;
    END IF;

    wanted_size := power(2::numeric, max_prefix_len - arg_wanted_prefix_len);

    -- scanning required pools
    FOR p IN SELECT generate_subscripts(arg_prefixes, 1) LOOP
        search_prefix := arg_prefixes[p];

        -- find prefix_id (necessary for find_free_ranges)
        SELECT id INTO prefix_id
        FROM ip_net_plan
        WHERE vrf_id = arg_vrf AND prefix = search_prefix
        LIMIT 1;

        IF prefix_id IS NULL THEN
            CONTINUE;
        END IF;

        -- free ranges -> free CIDR 
        free_ranges := ARRAY(SELECT find_free_ranges(prefix_id));
        free_cidrs  := ARRAY(SELECT iprange2cidr(free_ranges));

        -- ranking: exact fit first ande then larger subnets to explode
        FOREACH candidate IN ARRAY free_cidrs LOOP
            -- ignore smaller subnets
            IF masklen(candidate) > arg_wanted_prefix_len THEN
                CONTINUE;
            END IF;

            -- deduplicate identical subnets in input
            IF candidate = ANY(seen_prefixes) THEN
                CONTINUE;
            END IF;

            IF masklen(candidate) = arg_wanted_prefix_len THEN
                -- Exact fit (waste = 0)
                exact_entries := array_append(exact_entries, candidate::text  '|0');
                seen_prefixes := array_append(seen_prefixes, candidate);
            ELSE
                -- larger subnet to explode after in wanted
                -- calculate waste of the source subnet: size(subnet) - size(wanted)
                waste := power(2::numeric, max_prefix_len - masklen(candidate)) - wanted_size;

                -- avoid pushing the same subnet twice
                subnet_entries := array_append(subnet_entries, candidate::text  '|' || waste::text);
                -- subnets are not added in seen_prefixes because the subprefixes have to be deduplicated
            END IF;
        END LOOP;
    END LOOP;

    -- 1) exact fit (waste=0), ordered by prefix
    FOR entry IN
        SELECT split_part(e, '|', 1)::cidr AS prefix,
               split_part(e, '|', 2)::numeric AS waste
        FROM unnest(exact_entries) e
        ORDER BY prefix ASC
    LOOP
        IF i_found >= arg_count THEN
            RETURN;
        END IF;

        RETURN NEXT entry.prefix;
        i_found := i_found + 1;
    END LOOP;
-- 2) derived from larger subnets, sorting subnets by increasing waste
    FOR entryb IN
        SELECT split_part(e, '|', 1)::cidr   AS subnet,
               split_part(e, '|', 2)::numeric AS waste
        FROM unnest(subnet_entries) e
        GROUP BY 1,2                   -- avoid duplicates from the same subnet
        ORDER BY waste ASC, subnet ASC
    LOOP
        subnet_cidr := entryb.subnet;

        -- first /wanted 
        generated := set_masklen(network(subnet_cidr), arg_wanted_prefix_len);

        -- generate /wanted as long as we stay within the subnet and arg_count is not exceeded
        WHILE iprange(generated::cidr) << iprange(subnet_cidr) LOOP
            EXIT WHEN i_found >= arg_count;

            -- final deduplication: avoid collisions with exact or other derivations
            IF NOT generated::cidr = ANY(seen_prefixes) THEN
                seen_prefixes := array_append(seen_prefixes, generated::cidr);
                RETURN NEXT generated::cidr;
                i_found := i_found + 1;
            END IF;

            -- next subnet of same size
            generated := set_masklen(broadcast(generated) + 1, arg_wanted_prefix_len);
        END LOOP;

        EXIT WHEN i_found >= arg_count;
    END LOOP;

    RETURN;
END;
$_$ LANGUAGE plpgsql;



--
-- Helper to sort VRF RTs
--
-- RTs are tricky to sort since they exist in two formats and have the classic
-- sorted-as-string-problem;
--
--      199:456
--     1234:456
--  1.3.3.7:456
--
CREATE OR REPLACE FUNCTION vrf_rt_order(arg_rt text) RETURNS bigint AS $_$
DECLARE
	part_one text;
	part_two text;
	ip text;
BEGIN
	BEGIN
		part_one := split_part(arg_rt, ':', 1)::bigint;
	EXCEPTION WHEN others THEN
		ip := split_part(arg_rt, ':', 1);
		part_one := (split_part(ip, '.', 1)::bigint << 24) +
					(split_part(ip, '.', 2)::bigint << 16) +
					(split_part(ip, '.', 3)::bigint << 8) +
					(split_part(ip, '.', 4)::bigint);
	END;

	part_two := split_part(arg_rt, ':', 2);

	RETURN (part_one::bigint << 32) + part_two::bigint;
END;
$_$ LANGUAGE plpgsql IMMUTABLE STRICT;

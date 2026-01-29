-- Insert sample security groups
INSERT INTO security_groups (id, guid, name, rules, staging_default, running_default, staging_spaces, running_spaces, hash) VALUES (
        9,
        '9bdb6f87-0d6b-4804-b8c4-d2fcc323924a',
        'global_bound_staging',
        '[{\"protocol\":\"tcp\",\"destination\":\"172.16.0.0/12\",\"ports\":\"80,443\",\"type\":0,\"code\":0,\"description\":\"Allow http and https traffic to DockerContainer\",\"log\":true}]',
        true,
        false,
        '[]',
        '[]',
        'a0f6a96f25e3278227aa67573696acc33c28053826be6e99ccf569767aa45598'
    );

-- -- Reset sequence to ensure proper auto-increment
SELECT setval('security_groups_id_seq', (SELECT COALESCE(MAX(id), 1) FROM security_groups));

-- -- Insert initial info entries
INSERT INTO security_groups_info (id, last_updated) VALUES (1, CURRENT_TIMESTAMP);
INSERT INTO policies_info (id, last_updated) VALUES (1, CURRENT_TIMESTAMP);
-- Insert sample security groups
INSERT INTO security_groups (id, guid, name, rules, staging_default, running_default, staging_spaces, running_spaces, hash) VALUES (
        8,
        '5ac67e6a-5ab4-4093-b427-acf484c45fbf',
        'global_bound_running',
        '[{\"protocol\":\"tcp\",\"destination\":\"172.16.0.0/12\",\"ports\":\"80,443\",\"type\":0,\"code\":0,\"description\":\"Allow http and https traffic to DockerContainer\",\"log\":true}]',
        false,
        true,
        '[]',
        '[]',
        'ca28eb652e4795a6b7ff2abeeb996a11bd68da1d6aadbe145f32fc6ec96c9f21'
    );

-- -- Reset sequence to ensure proper auto-increment
SELECT setval('security_groups_id_seq', (SELECT COALESCE(MAX(id), 1) FROM security_groups));

-- -- Insert initial info entries
INSERT INTO security_groups_info (id, last_updated) VALUES (2, CURRENT_TIMESTAMP);
INSERT INTO policies_info (id, last_updated) VALUES (2, CURRENT_TIMESTAMP);
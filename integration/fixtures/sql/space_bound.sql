-- Insert sample security groups
INSERT INTO security_groups (id, guid, name, rules, staging_default, running_default, staging_spaces, running_spaces, hash) VALUES (
        17,
        'c137fc2e-ce65-4b69-9770-079a17f1fff9',
        'space_bound',
        '[{\"protocol\":\"tcp\",\"destination\":\"172.16.0.0/12\",\"ports\":\"80,443\",\"type\":0,\"code\":0,\"description\":\"Allow http and https traffic to DockerContainer\",\"log\":true}]',
        false,
        false,
        '[\"ac3026c1-56f5-4695-b6bc-922ac44dc386\"]',
        '[\"ac3026c1-56f5-4695-b6bc-922ac44dc386\"]',
        '81bdc4a19f8d4def96f687ffa4a29f6fe33156dd0c7e1df861459d7008289840'
    );

-- -- Reset sequence to ensure proper auto-increment
SELECT setval('security_groups_id_seq', (SELECT COALESCE(MAX(id), 1) FROM security_groups));

-- -- Insert related space mappings
INSERT INTO running_security_groups_spaces (space_guid, security_group_guid) VALUES
('ac3026c1-56f5-4695-b6bc-922ac44dc386', 'c137fc2e-ce65-4b69-9770-079a17f1fff9');

-- -- Insert initial info entries
INSERT INTO security_groups_info (id, last_updated) VALUES (3, CURRENT_TIMESTAMP);
INSERT INTO policies_info (id, last_updated) VALUES (3, CURRENT_TIMESTAMP);
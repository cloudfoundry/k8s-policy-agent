-- Insert sample security groups
INSERT INTO security_groups (id, guid, name, rules, staging_default, running_default, staging_spaces, running_spaces, hash) VALUES (
        27,
        'c8f7e3a1-d9b2-4e6f-a5c8-1f4b7e9d2a6c',
        'icmp',
        '[{\"protocol\":\"icmp\",\"destination\":\"172.16.0.0/12\",\"type\":8,\"code\":-1,\"description\":\"Allow ping request to DockerContainer\",\"log\":true}]',
        false,
        false,
        '[]',
        '[\"ac3026c1-56f5-4695-b6bc-922ac44dc386\"]',
        '81bdc4a19f8d4def96f687ffa4a29f6fe33156dd0c7e1df861459d7008289840'
    );

-- -- Reset sequence to ensure proper auto-increment
SELECT setval('security_groups_id_seq', (SELECT COALESCE(MAX(id), 1) FROM security_groups));

-- -- Insert related space mappings
INSERT INTO running_security_groups_spaces (space_guid, security_group_guid) VALUES
('ac3026c1-56f5-4695-b6bc-922ac44dc386', 'c8f7e3a1-d9b2-4e6f-a5c8-1f4b7e9d2a6c');

-- -- Insert initial info entries
INSERT INTO security_groups_info (id, last_updated) VALUES (3, CURRENT_TIMESTAMP);
INSERT INTO policies_info (id, last_updated) VALUES (3, CURRENT_TIMESTAMP);
-- Insert sample security groups
INSERT INTO security_groups (id, guid, name, rules, staging_default, running_default, staging_spaces, running_spaces, hash) VALUES (
        10,
        'c5abb8a6-812e-4f29-9de4-0723250ebfa9',
        'different_space_bound',
        '[{\"protocol\":\"tcp\",\"destination\":\"172.16.0.0/12\",\"ports\":\"80,443\",\"type\":0,\"code\":0,\"description\":\"Allow http and https traffic to DockerContainer\",\"log\":true}]',
        false,
        false,
        '[]',
        '[\"91711770-bf70-4cfa-9df2-56e341dfee8a\"]',
        'f99181fa656c8b2c1845cfb11352a0795318c6e32096ccee38706ff9afd8fa28'
    );

-- -- Reset sequence to ensure proper auto-increment
SELECT setval('security_groups_id_seq', (SELECT COALESCE(MAX(id), 1) FROM security_groups));

INSERT INTO running_security_groups_spaces (space_guid, security_group_guid) VALUES
('91711770-bf70-4cfa-9df2-56e341dfee8a', 'c5abb8a6-812e-4f29-9de4-0723250ebfa9');

-- -- Insert initial info entries
INSERT INTO security_groups_info (id, last_updated) VALUES (4, CURRENT_TIMESTAMP);
INSERT INTO policies_info (id, last_updated) VALUES (4, CURRENT_TIMESTAMP);
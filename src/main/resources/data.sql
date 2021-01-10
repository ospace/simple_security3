-- password: 1111
INSERT INTO `users`(`username`, `password`, `enabled`)
VALUES ('admin', '$2a$10$.qPMRoGUXR0vkDeWVBDZ2OGhcRW5rYDzulUjMMXKZZ.POxXViu7hi', TRUE);

INSERT INTO `users`(`username`, `password`, `enabled`)
VALUES ('user', '$2a$10$.qPMRoGUXR0vkDeWVBDZ2OGhcRW5rYDzulUjMMXKZZ.POxXViu7hi', TRUE);

INSERT INTO `users`(`username`, `password`, `enabled`)
VALUES ('master', '$2a$10$.qPMRoGUXR0vkDeWVBDZ2OGhcRW5rYDzulUjMMXKZZ.POxXViu7hi', TRUE);

INSERT INTO `authorities`(`username`, `authority`)
VALUES ('admin', 'ROLE_ADMIN');

INSERT INTO `authorities`(`username`, `authority`)
VALUES ('user', 'ROLE_USER');

INSERT INTO `groups`(`group_name`)
VALUES ('administrator');

INSERT INTO `group_authorities`(`group_id`, `authority`)
VALUES (1, 'ROLE_ADMIN');

INSERT INTO `group_authorities`(`group_id`, `authority`)
VALUES (1, 'ROLE_USER');

INSERT INTO `group_members`(`id`, `username`, `group_id`)
VALUES (1, 'master', 1);

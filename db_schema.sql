CREATE TABLE IF NOT EXISTS job(
	`id` int NOT NULL AUTO_INCREMENT,
	`user` varchar(50) NOT NULL,
	`job` varchar(50) NOT NULL,
	`name` text NOT NULL,
	`status` text NOT NULL,
	`time_start` datetime,
	`time_complete` datetime,
	`type` text NOT NULL,
	`query` MEDIUMTEXT NOT NULL,
	`files` MEDIUMTEXT NOT NULL,
	`sizes` text NOT NULL,
	`runtime` int NOT NULL,
	`apitoken` char(32) NOT NULL,
	`spec` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS account(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`full_name` text NOT NULL,
	`email` text NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS session(
	`id` int NOT NULL AUTO_INCREMENT,
	`account_id` int NOT NULL,
	`token_refreshed` datetime,
	`token_value` varchar(65) NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS role_binding(
	`id` int NOT NULL AUTO_INCREMENT,
	`account_id` int NOT NULL,
	`role_id` int NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS role(
	`id` int NOT NULL AUTO_INCREMENT,
	`role_name` text NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
INSERT INTO role (`role_name`) VALUES ('admin')
#---
INSERT INTO role (`role_name`) VALUES ('collaborator')
#---
INSERT INTO role (`role_name`) VALUES ('public')
#---
# TODO: Remove these hard-coded initialization statements prior to committing
#---
INSERT INTO account (`username`, `full_name`, `email`) VALUES('michael', 'Michael Johnson', 'mjohns44@illinois.edu')
#---
INSERT INTO role_binding (`account_id`, `role_id`) VALUES(1, 1)
#---
INSERT INTO account (`username`, `full_name`, `email`) VALUES('andrew', 'Timothy Andrew Manning', 'manninga@illinois.edu')
#---
INSERT INTO role_binding (`account_id`, `role_id`) VALUES(2, 1)
#---
INSERT INTO account (`username`, `full_name`, `email`) VALUES('matias', 'Matias Carrasco Kind', 'mcarras2@illinois.edu')
#---
INSERT INTO role_binding (`account_id`, `role_id`) VALUES(3, 1)
#---

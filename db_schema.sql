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

CREATE TABLE IF NOT EXISTS user(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`full_name` text NOT NULL,
	`email` text NOT NULL,
	`token_issued` datetime,
	`token_value` varchar(65) NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

CREATE TABLE IF NOT EXISTS session(
	`id` int NOT NULL AUTO_INCREMENT,
	`user_id` varchar(50) NOT NULL,
	`token_refreshed` datetime,
	`token_value` varchar(65) NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

CREATE TABLE IF NOT EXISTS group_membership(
	`id` int NOT NULL AUTO_INCREMENT,
	`user_id` int NOT NULL,
	`group_id` int NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

CREATE TABLE IF NOT EXISTS group(
	`id` int NOT NULL AUTO_INCREMENT,
	`group_name` int NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

INSERT INTO group ('group_name') VALUES('admin')
INSERT INTO group ('group_name') VALUES('collaborator')
INSERT INTO group ('group_name') VALUES('public')

# TODO: Remove these hard-coded initialization statements prior to committing
INSERT INTO user ('username', 'full_name', 'email') VALUES('michael', 'Michael Johnson', 'mjohns44@illinois.edu')
INSERT INTO group_membership ('user_id', 'group_id') VALUES(1, 1)
INSERT INTO user ('username', 'full_name', 'email') VALUES('andrew', 'Timothy Andrew Manning', 'manninga@illinois.edu')
INSERT INTO group_membership ('user_id', 'group_id') VALUES(2, 1)
INSERT INTO user ('username', 'full_name', 'email') VALUES('matias', 'Matias Carrasco Kind', 'mcarras2@illinois.edu')
INSERT INTO group_membership ('user_id', 'group_id') VALUES(3, 1)

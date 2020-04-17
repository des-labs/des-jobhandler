CREATE TABLE IF NOT EXISTS job(
	`id` int NOT NULL AUTO_INCREMENT,
	`user` varchar(50) NOT NULL,
	`type` varchar(50) NOT NULL,
	`uuid` text NOT NULL,
	`status` text NOT NULL,
	`time_start` datetime,
	`time_complete` datetime,
	`apitoken` char(32) NOT NULL,
	`spec` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS session(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`token_refreshed` datetime,
	`token_value` text NOT NULL,
	`password` text,
	KEY (`id`),
	PRIMARY KEY (`username`),
	UNIQUE KEY `username` (`username`)
)
#---
CREATE TABLE IF NOT EXISTS role(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`role_name` text NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS query(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`query` MEDIUMTEXT NOT NULL,
	`file_info` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

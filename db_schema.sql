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

CREATE TABLE IF NOT EXISTS `message`(
	`id` int NOT NULL AUTO_INCREMENT,
	`date` datetime DEFAULT 0,
	`title` varchar(512) NOT NULL,
	`body` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `message_role`(
	`id` int NOT NULL AUTO_INCREMENT,
	`message_id` int NOT NULL,
	`role_name` text NOT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `message_read`(
	`id` int NOT NULL AUTO_INCREMENT,
	`message_id` int NOT NULL,
	`username` varchar(50) NOT NULL,
	PRIMARY KEY (`id`),
	UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `user_preferences`(
	`id` int NOT NULL AUTO_INCREMENT,
	`preferences` MEDIUMTEXT NOT NULL,
	`username` varchar(50) NOT NULL,
	KEY (`id`),
	PRIMARY KEY (`username`),
	UNIQUE KEY `username` (`username`)
)

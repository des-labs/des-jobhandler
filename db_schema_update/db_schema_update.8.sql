CREATE TABLE IF NOT EXISTS `help`(
	`id` int NOT NULL AUTO_INCREMENT,
	`user` varchar(50) NOT NULL,
	`firstname` varchar(128) NOT NULL,
	`lastname` varchar(128) NOT NULL,
	`email` varchar(128) NOT NULL,
	`message` MEDIUMTEXT NOT NULL,
	`topics` MEDIUMTEXT NOT NULL,
	`othertopic` varchar(128) NOT NULL DEFAULT '',
	`jira_issue` varchar(64) NOT NULL DEFAULT '',
	`resolved` boolean DEFAULT 0,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

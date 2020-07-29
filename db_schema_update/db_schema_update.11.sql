CREATE TABLE IF NOT EXISTS `cron`(
	`id` int NOT NULL AUTO_INCREMENT,
	`name` varchar(128) NOT NULL,
	`period` int NOT NULL,
	`last_run` datetime DEFAULT 0,
	`enabled` boolean DEFAULT 0,
	PRIMARY KEY (`id`),
	UNIQUE KEY `name` (`name`)
)
#---
INSERT INTO `cron` (`name`, `period`, `enabled`) VALUES ('jupyter_prune', 60, 1)
CREATE TABLE IF NOT EXISTS `analytics`(
	`id` int NOT NULL AUTO_INCREMENT,
	`request_path` varchar(128) NOT NULL,
	`call_time` datetime DEFAULT 0,
	`user_agent` text NOT NULL DEFAULT '',
	`remote_ip` varchar(50),
	PRIMARY KEY (`id`),
	UNIQUE KEY `id` (`id`)
)
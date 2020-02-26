CREATE TABLE IF NOT EXISTS Jobs(
	`id` int(11) NOT NULL AUTO_INCREMENT,
	`user` varchar(50) NOT NULL,
	`job` varchar(50) NOT NULL,
	`name` text NOT NULL,
	`status` text NOT NULL,
	`time` datetime NOT NULL,
	`type` text NOT NULL,
	`query` mediumtext NOT NULL,
	`files` mediumtext NOT NULL,
	`sizes` text NOT NULL,
	`runtime` int NOT NULL,
  PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)

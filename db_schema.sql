CREATE TABLE IF NOT EXISTS Jobs(
	`id` int(11) NOT NULL AUTO_INCREMENT,
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

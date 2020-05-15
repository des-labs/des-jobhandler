CREATE TABLE IF NOT EXISTS `job`(
	`id` int NOT NULL AUTO_INCREMENT,
	`user` varchar(50) NOT NULL,
	`type` varchar(50) NOT NULL,
	`name` varchar(128) NOT NULL,
	`uuid` text NOT NULL,
	`status` text NOT NULL,
	`time_start` datetime DEFAULT 0,
	`time_complete` datetime DEFAULT 0,
	`apitoken` char(32) NOT NULL,
	`msg` MEDIUMTEXT NOT NULL DEFAULT '',
	`user_agent` TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `session`(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`last_login` datetime DEFAULT 0,
	`token_value` text NOT NULL,
	`password` text,
	KEY (`id`),
	PRIMARY KEY (`username`),
	UNIQUE KEY `username` (`username`)
)
#---
CREATE TABLE IF NOT EXISTS `role`(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`role_name` text NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `query`(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`query` MEDIUMTEXT NOT NULL,
	`files` MEDIUMTEXT NOT NULL,
	`sizes` MEDIUMTEXT NOT NULL,
	`data` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `cutout`(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`db` varchar(50) NOT NULL,
	`release` varchar(50) NOT NULL,
	`ra` MEDIUMTEXT,
	`dec` MEDIUMTEXT,
	`coadd` MEDIUMTEXT,
	`xsize` float,
	`ysize` float,
	`make_fits` boolean DEFAULT 0,
	`make_tiffs` boolean DEFAULT 0,
	`make_pngs` boolean DEFAULT 0,
	`make_rgb_lupton` boolean DEFAULT 0,
	`make_rgb_stiff` boolean DEFAULT 0,
	`return_list` boolean DEFAULT 0,
	`colors_fits` MEDIUMTEXT,
	`colors_rgb` MEDIUMTEXT,
	`rgb_minimum` float,
	`rgb_stretch` float,
	`rgb_asinh` float,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `meta`(
	`Lock` char(1) NOT NULL DEFAULT 'X',
	`schema_version` int NOT NULL DEFAULT 0,
	constraint PK_T1 PRIMARY KEY (`Lock`),
	constraint CK_T1_Locked CHECK (`Lock`='X')
)

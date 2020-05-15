ALTER TABLE `job` DROP COLUMN `spec`
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

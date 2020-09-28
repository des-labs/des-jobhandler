CREATE TABLE IF NOT EXISTS `job_renewal`(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`renewal_date` datetime NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `job_renewal_token`(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`renewal_token` char(32) NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
INSERT INTO `cron` (`name`, `period`, `enabled`) VALUES ('prune_job_files', 360, 1)
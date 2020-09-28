CREATE TABLE IF NOT EXISTS `job_renewal`(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`renewals_used` int NOT NULL,
	`renewals_left` int NOT NULL,
	`expiration_date` datetime NOT NULL,
	`renewal_token` char(32),
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
INSERT INTO `cron` (`name`, `period`, `enabled`) VALUES ('prune_job_files', 360, 1)
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `ra`
#---
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `dec`
#---
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `coadd`
#---
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `make_pngs`
#---
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `make_tiffs`
#---
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `colors_rgb`
#---
ALTER TABLE `cutout` DROP COLUMN IF EXISTS `return_list`
#---
ALTER TABLE `cutout` ADD `rgb_stiff_colors` MEDIUMTEXT
#---
ALTER TABLE `cutout` ADD `rgb_lupton_colors` MEDIUMTEXT
#---
ALTER TABLE `cutout` ADD `summary` LONGTEXT
#---
#ifndef ACEDIA_DEV_H
#define ACEDIA_DEV_H

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>   
#include <linux/module.h>  
#include <linux/slab.h>  
#include <asm/ioctl.h>

#include "acedia.h"

ssize_t acedia_dev_read(struct file *file, char *buffer,
				size_t length, loff_t *offset);

int acedia_dev_ioctl(struct inode *inode, struct file *file,
		unsigned int ioctl_num, unsigned long ioctl_param);

int acedia_dev_release(struct inode *inode, struct file *file);

int acedia_dev_open(struct inode *inode, struct file *file);

#endif

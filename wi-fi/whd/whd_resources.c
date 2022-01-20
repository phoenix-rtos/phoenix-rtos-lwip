/*
 * Copyright 2021, Cypress Semiconductor Corporation (an Infineon company)
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** @file
 * Defines WHD resource functions for AW-NM512 platform
 */
#include "whd_resource_api.h"
#include "whd_chip_constants.h"
#include "wifi_nvram_image.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


#define AW_NM512_FIRMWARE_FILENAME     "/firmware/43439A0.bin"
#define AW_NM512_CLM_FILENAME          "/firmware/43439A0.clm_blob"
#define STERLING_LWB_FIRMWARE_FILENAME "/firmware/brcmfmac43430-sdio-prod.bin"
#define STERLING_LWB_CLM_FILENAME      "/firmware/brcmfmac43430-sdio.clm_blob"


static uint8_t resource_buf[BLOCK_SIZE];


off_t get_file_size(const char *filename)
{
	struct stat st;

	if (stat(filename, &st) < 0)
		return -1;
	return st.st_size;
}


int read_file(const char *filename, off_t pos, size_t len, uint8_t *buf)
{
	FILE *file;
	size_t n;

	file = fopen(filename, "r");
	if (!file)
		return -1;

	if (fseek(file, pos, SEEK_SET) < 0) {
		fclose(file);
		return -1;
	}

	n = fread(buf, len, 1, file);

	fclose(file);

	return (n == len);
}


static const char *host_firmware_filename(whd_driver_t whd_drv)
{
	uint16_t chip_id = whd_chip_get_chip_id(whd_drv);

	if (chip_id == 43430)
		return STERLING_LWB_FIRMWARE_FILENAME;
	else if (chip_id == 43439)
		return AW_NM512_FIRMWARE_FILENAME;
	else
		return NULL;
}


static const char *host_clm_filename(whd_driver_t whd_drv)
{
	uint16_t chip_id = whd_chip_get_chip_id(whd_drv);

	if (chip_id == 43430)
		return STERLING_LWB_CLM_FILENAME;
	else if (chip_id == 43439)
		return AW_NM512_CLM_FILENAME;
	else
		return NULL;
}


static const char *host_nvram_image(whd_driver_t whd_drv)
{
	uint16_t chip_id = whd_chip_get_chip_id(whd_drv);

	if (chip_id == 43430)
		return sterling_lwb_wifi_nvram_image;
	else if (chip_id == 43439)
		return aw_nm512_wifi_nvram_image;
	else
		return NULL;
}


static ssize_t host_nvram_size(whd_driver_t whd_drv)
{
	uint16_t chip_id = whd_chip_get_chip_id(whd_drv);

	if (chip_id == 43430)
		return sizeof(sterling_lwb_wifi_nvram_image);
	else if (chip_id == 43439)
		return sizeof(aw_nm512_wifi_nvram_image);
	else
		return -1;
}


uint32_t host_resource_size(whd_driver_t whd_drv, whd_resource_type_t resource, uint32_t *size_out)
{
	const char *filename;
	off_t fsize;
	ssize_t isize;

	switch (resource) {
		case WHD_RESOURCE_WLAN_FIRMWARE:
			filename = host_firmware_filename(whd_drv);
			if (filename == NULL)
				return WHD_HAL_ERROR;
			if ((fsize = get_file_size(filename)) < 0)
				return WHD_HAL_ERROR;
			*size_out = fsize;
			break;
		case WHD_RESOURCE_WLAN_NVRAM:
			isize = host_nvram_size(whd_drv);
			if (isize < 0)
				return WHD_HAL_ERROR;
			*size_out = isize;
			break;
		case WHD_RESOURCE_WLAN_CLM:
			filename = host_clm_filename(whd_drv);
			if (filename == NULL)
				return WHD_HAL_ERROR;
			if ((fsize = get_file_size(filename)) < 0)
				return WHD_HAL_ERROR;
			*size_out = fsize;
			break;
		default:
			return WHD_BADARG;
	}

	return WHD_SUCCESS;
}


uint32_t host_get_resource_block_size(whd_driver_t whd_drv, whd_resource_type_t type, uint32_t *size_out)
{
	*size_out = BLOCK_SIZE;
	return WHD_SUCCESS;
}


uint32_t host_get_resource_no_of_blocks(whd_driver_t whd_drv, whd_resource_type_t type, uint32_t *block_count)
{
	uint32_t result, resource_size;

	if ((result = host_resource_size(whd_drv, type, &resource_size)) != WHD_SUCCESS)
		return result;
	*block_count = (resource_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
	return WHD_SUCCESS;
}


uint32_t host_get_resource_block(whd_driver_t whd_drv, whd_resource_type_t type, uint32_t blockno, const uint8_t **data, uint32_t *size_out)
{
	const char *filename, *image;
	uint32_t result, resource_size, block_count, block_pos, block_size;

	if ((result = host_resource_size(whd_drv, type, &resource_size)) != WHD_SUCCESS)
		return result;

	if ((result = host_get_resource_no_of_blocks(whd_drv, type, &block_count)) != WHD_SUCCESS)
		return result;

	if (blockno >= block_count)
		return WHD_BADARG;

	block_pos = blockno * BLOCK_SIZE;

	if (block_pos + BLOCK_SIZE <= resource_size)
		block_size = BLOCK_SIZE;
	else
		block_size = resource_size - block_pos;

	memset(resource_buf, 0, sizeof(resource_buf));

	switch (type) {
		case WHD_RESOURCE_WLAN_FIRMWARE:
			filename = host_firmware_filename(whd_drv);
			if (filename == NULL)
				return WHD_HAL_ERROR;
			if (read_file(filename, block_pos, block_size, resource_buf) < 0)
				return WHD_HAL_ERROR;
			break;
		case WHD_RESOURCE_WLAN_NVRAM:
			image = host_nvram_image(whd_drv);
			if (image == NULL)
				return WHD_HAL_ERROR;
			memcpy(resource_buf, image + block_pos, block_size);
			break;
		case WHD_RESOURCE_WLAN_CLM:
			filename = host_clm_filename(whd_drv);
			if (filename == NULL)
				return WHD_HAL_ERROR;
			if (read_file(filename, block_pos, block_size, resource_buf) < 0)
				return WHD_HAL_ERROR;
			break;
		default:
			return WHD_BADARG;
	}

	*data = resource_buf;
	*size_out = block_size;

	return WHD_SUCCESS;
}


whd_resource_source_t resource_ops = {
	.whd_resource_size = host_resource_size,
	.whd_get_resource_block_size = host_get_resource_block_size,
	.whd_get_resource_no_of_blocks = host_get_resource_no_of_blocks,
	.whd_get_resource_block = host_get_resource_block
};

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
#include "wifi_nvram_image.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


// #define FIRMWARE_FILENAME "/firmware/brcmfmac43439-sdio.bin"
// #define CLM_FILENAME      "/firmware/brcmfmac43439-sdio.clm_blob"
// #define FIRMWARE_FILENAME "/firmware/43439A0.bin"
// #define CLM_FILENAME      "/firmware/43439A0.clm_blob"
#define FIRMWARE_FILENAME "/firmware/brcmfmac43430-sdio-prod.bin"
#define CLM_FILENAME      "/firmware/brcmfmac43430-sdio.clm_blob"


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


uint32_t host_resource_size(whd_driver_t whd_drv, whd_resource_type_t resource, uint32_t *size_out)
{
	off_t fsize;

	switch (resource) {
		case WHD_RESOURCE_WLAN_FIRMWARE:
			if ((fsize = get_file_size(FIRMWARE_FILENAME)) < 0)
				return WHD_HAL_ERROR;
			*size_out = fsize;
			break;
		case WHD_RESOURCE_WLAN_NVRAM:
			*size_out = sizeof(wifi_nvram_image);
			break;
		case WHD_RESOURCE_WLAN_CLM:
			if ((fsize = get_file_size(CLM_FILENAME)) < 0)
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
			if (read_file(FIRMWARE_FILENAME, block_pos, block_size, resource_buf) < 0)
				return WHD_HAL_ERROR;
			break;
		case WHD_RESOURCE_WLAN_NVRAM:
			memcpy(resource_buf, wifi_nvram_image + block_pos, block_size);
			break;
		case WHD_RESOURCE_WLAN_CLM:
			if (read_file(CLM_FILENAME, block_pos, block_size, resource_buf) < 0)
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

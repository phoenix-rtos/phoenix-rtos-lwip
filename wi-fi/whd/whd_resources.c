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

#include "lwipopts.h"
#include "wifi_nvram_image.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>


#ifndef WIFI_FIRMWARE_FILES_DIRECTORY_PATH
#define WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/firmware"
#endif

#ifndef FIRMWARE_FILE_EXTENSION
#define FIRMWARE_FILE_EXTENSION ".bin"
#endif

#ifndef CLM_FILE_EXTENSION
#define CLM_FILE_EXTENSION ".clm_blob"
#endif

#ifndef NVRAM_FILE_EXTENSION
#define NVRAM_FILE_EXTENSION ".nvram_blob"
#endif

#define AW_NM512_FILENAME     "43439A0"
#define STERLING_LWB_FILENAME "brcmfmac43430-sdio-prod"


static uint8_t resource_buf[BLOCK_SIZE];

static const struct chip_lookup {
	uint16_t chip_id;
	struct resource {
		const char *path;
		const char *mem_image;
		uint32_t mem_size;
	} rsrc[3];
} chip_resources[] = {
	{
		.chip_id = 43430,
		.rsrc = {
			[WHD_RESOURCE_WLAN_FIRMWARE] = {
				.path = WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/" STERLING_LWB_FILENAME FIRMWARE_FILE_EXTENSION,
				.mem_image = NULL,
				.mem_size = 0,
			},
			[WHD_RESOURCE_WLAN_NVRAM] = {
				.path = WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/" STERLING_LWB_FILENAME NVRAM_FILE_EXTENSION,
				.mem_image = sterling_lwb_wifi_nvram_image,
				.mem_size = sizeof(sterling_lwb_wifi_nvram_image),
			},
			[WHD_RESOURCE_WLAN_CLM] = {
				.path = WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/" STERLING_LWB_FILENAME CLM_FILE_EXTENSION,
				.mem_image = NULL,
				.mem_size = 0,
			},
		},
	},
	{
		.chip_id = 43439,
		.rsrc = {
			[WHD_RESOURCE_WLAN_FIRMWARE] = {
				.path = WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/" AW_NM512_FILENAME FIRMWARE_FILE_EXTENSION,
				.mem_image = NULL,
				.mem_size = 0,
			},
			[WHD_RESOURCE_WLAN_NVRAM] = {
				.path = WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/" AW_NM512_FILENAME NVRAM_FILE_EXTENSION,
				.mem_image = aw_nm512_wifi_nvram_image,
				.mem_size = sizeof(aw_nm512_wifi_nvram_image),
			},
			[WHD_RESOURCE_WLAN_CLM] = {
				.path = WIFI_FIRMWARE_FILES_DIRECTORY_PATH "/" AW_NM512_FILENAME CLM_FILE_EXTENSION,
				.mem_image = NULL,
				.mem_size = 0,
			},
		},
	},
};


static ssize_t get_file_size(const char *filename)
{
	struct stat st;

	if (stat(filename, &st) < 0) {
		return -1;
	}

	/* Sanity checks on the value - we don't expect any firmware to be over 2 GB */
	if ((st.st_size > INT32_MAX) || (st.st_size < 0)) {
		return -1;
	}

	return (ssize_t)st.st_size;
}


static int read_file(const char *filename, off_t pos, size_t len, uint8_t *buf)
{
	FILE *file;

	file = fopen(filename, "rb");
	if (file == NULL) {
		return -1;
	}

	if (fseek(file, pos, SEEK_SET) < 0) {
		fclose(file);
		return -1;
	}

	size_t read_size = fread(buf, 1, len, file);
	int ret = (read_size == len) ? 0 : -1;
	fclose(file);
	return ret;
}


static uint32_t resource_lookup(whd_driver_t whd_drv, whd_resource_type_t resource, const struct resource **rsrc, bool *is_memory, uint32_t *size_out)
{
	if ((resource != WHD_RESOURCE_WLAN_CLM) &&
			(resource != WHD_RESOURCE_WLAN_FIRMWARE) &&
			(resource != WHD_RESOURCE_WLAN_NVRAM)) {
		return WHD_BADARG;
	}

	const struct chip_lookup *lookup = NULL;
	uint16_t chip_id = whd_chip_get_chip_id(whd_drv);
	for (size_t i = 0; i < sizeof(chip_resources) / sizeof(chip_resources[0]); i++) {
		if (chip_id == chip_resources[i].chip_id) {
			lookup = &chip_resources[i];
			break;
		}
	}

	if (lookup == NULL) {
		return WHD_HAL_ERROR;
	}

	if (rsrc != NULL) {
		*rsrc = &lookup->rsrc[resource];
	}

	ssize_t fsize;
	if (lookup->rsrc[resource].path == NULL) {
		fsize = -1;
	}
	else {
		fsize = get_file_size(lookup->rsrc[resource].path);
	}

	if (fsize < 0) {
		if (lookup->rsrc[resource].mem_image == NULL) {
			return WHD_HAL_ERROR;
		}

		*is_memory = true;
		*size_out = lookup->rsrc[resource].mem_size;
	}
	else {
		*is_memory = false;
		*size_out = (uint32_t)fsize;
	}

	return WHD_SUCCESS;
}


static inline uint32_t calculate_block_count(uint32_t resource_size)
{
	return (resource_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
}


uint32_t host_resource_size(whd_driver_t whd_drv, whd_resource_type_t resource, uint32_t *size_out)
{
	bool ignored;
	return resource_lookup(whd_drv, resource, NULL, &ignored, size_out);
}


uint32_t host_get_resource_block_size(whd_driver_t whd_drv, whd_resource_type_t type, uint32_t *size_out)
{
	*size_out = BLOCK_SIZE;
	return WHD_SUCCESS;
}


uint32_t host_get_resource_no_of_blocks(whd_driver_t whd_drv, whd_resource_type_t type, uint32_t *block_count)
{
	uint32_t result, resource_size;

	result = host_resource_size(whd_drv, type, &resource_size);
	if (result != WHD_SUCCESS) {
		return result;
	}

	*block_count = calculate_block_count(resource_size);
	return WHD_SUCCESS;
}


uint32_t host_get_resource_block(whd_driver_t whd_drv, whd_resource_type_t type, uint32_t blockno, const uint8_t **data, uint32_t *size_out)
{
	uint32_t result, resource_size, block_count, block_pos, block_size;
	const struct resource *rsrc;
	bool is_memory;

	result = resource_lookup(whd_drv, type, &rsrc, &is_memory, &resource_size);
	if (result != WHD_SUCCESS) {
		return result;
	}

	block_count = calculate_block_count(resource_size);
	if (blockno >= block_count) {
		return WHD_BADARG;
	}

	block_pos = blockno * BLOCK_SIZE;

	if (block_pos + BLOCK_SIZE <= resource_size) {
		block_size = BLOCK_SIZE;
	}
	else {
		block_size = resource_size - block_pos;
	}

	memset(resource_buf, 0, sizeof(resource_buf));

	if (is_memory) {
		memcpy(resource_buf, rsrc->mem_image + block_pos, block_size);
	}
	else {
		if (read_file(rsrc->path, block_pos, block_size, resource_buf) < 0) {
			return WHD_HAL_ERROR;
		}
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

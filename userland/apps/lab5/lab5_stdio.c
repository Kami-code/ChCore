/*
 * Copyright (c) 2022 Institute of Parallel And Distributed Systems (IPADS)
 * ChCore-Lab is licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 */

#include "lab5_stdio.h"


extern struct ipc_struct *tmpfs_ipc_struct;

/* You could add new functions or include headers here.*/
/* LAB 5 TODO BEGIN */

void fill_lseek(struct fs_request* fr, int fd, int offset) {
	fr->req = FS_REQ_LSEEK;
	fr->lseek.fd = fd;
	fr->lseek.offset = offset;
	fr->lseek.whence = SEEK_SET;
}

void fill_write(struct fs_request* fr, int fd, int nmemb) {
	fr->req = FS_REQ_WRITE;
	fr->write.count = nmemb;
	fr->write.fd = fd;	
}

void fill_read(struct fs_request* fr, int fd, int nmemb) {
	fr->req = FS_REQ_READ;
	fr->read.fd = fd;
	fr->read.count = nmemb;
}

void fill_close(struct fs_request* fr, int fd) {
	fr->req = FS_REQ_CLOSE;
	fr->close.fd = fd;
}

int alloc_id() {
	static int fd = 0;
	return ++fd;
}


void fill_open(struct fs_request* fr, int fd, unsigned int mode) {
	fr->req = FS_REQ_OPEN;
	fr->open.new_fd = fd;
	fr->open.mode = mode;
}


/* LAB 5 TODO END */


FILE *fopen(const char * filename, const char * mode) {

	/* LAB 5 TODO BEGIN */
	ipc_msg_t* ipc_msg;
	int ret, fd = alloc_id();
	struct fs_request* fr_ptr;
begin:
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
	fill_open(fr_ptr, fd, (unsigned int)mode);

	if (strlen(filename) == 0) strcpy((void *) fr_ptr->open.pathname, "/");
	else if (*filename != '/') {
		fr_ptr->open.pathname[0] = '/';
		strcpy((void *) (fr_ptr->open.pathname + 1), filename);
	} 
	else strcpy((void *) fr_ptr->open.pathname, filename);

	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);

	if (ret < 0) if (*mode == 'r') goto error;
	else {
		ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
		fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
		fr_ptr->req = FS_REQ_CREAT;
		fr_ptr->creat.mode = (unsigned int) mode;
		if (strlen(filename) == 0) strcpy((void *) fr_ptr->creat.pathname, "/");
		else if (*filename != '/') {
			fr_ptr->creat.pathname[0] = '/';
			strcpy((void *) (fr_ptr->creat.pathname + 1), filename);
		} 
		else strcpy((void *) fr_ptr->creat.pathname, filename);
		ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
		ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
		if (ret < 0) goto error;
		goto begin;
	}
	FILE* file = malloc(sizeof(struct FILE));
	file->fd = fd;
	strcpy(file->filename, filename);
	file->mode = (unsigned int) mode;
	file->offset = 0;
	/* LAB 5 TODO END */
error:
    return file;
}



size_t fwrite(const void * src, size_t size, size_t nmemb, FILE * f) {

	/* LAB 5 TODO BEGIN */
	ipc_msg_t* ipc_msg;
	int ret, fd = f->fd;
	struct fs_request* fr_ptr;
	
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
	fill_lseek(fr_ptr, fd, f->offset);
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	if (ret < 0)
		goto error;

	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request) + nmemb + 1, 1);
	fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
	fill_write(fr_ptr, fd, nmemb);
	memcpy((void *) fr_ptr + sizeof(struct fs_request), src, nmemb);
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	if (ret < 0)
		goto error;
	f->offset += ret;

	/* LAB 5 TODO END */
error:
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
    	return ret;
}





size_t fread(void * destv, size_t size, size_t nmemb, FILE * f) {

	/* LAB 5 TODO BEGIN */
	ipc_msg_t* ipc_msg;
	int ret, fd = f->fd;
	struct fs_request* fr_ptr;
	
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
	fill_lseek(fr_ptr, f->fd, f->offset);
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	if (ret < 0) goto error;
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
	fill_read(fr_ptr, fd, nmemb);

	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	if (ret <= 0)
		goto error;
	
	memcpy(destv, ipc_get_msg_data(ipc_msg), ret);

	f->offset += ret;
	
	/* LAB 5 TODO END */
error:
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
    	return ret;
}



int fclose(FILE *f) {

	/* LAB 5 TODO BEGIN */
	ipc_msg_t* ipc_msg;
	int ret, fd = f->fd;
	struct fs_request* fr_ptr;
	ipc_msg = ipc_create_msg(tmpfs_ipc_struct, sizeof(struct fs_request), 1);
	fr_ptr = (struct fs_request *) ipc_get_msg_data(ipc_msg);
	fill_close(fr_ptr, fd);
	ret = ipc_call(tmpfs_ipc_struct, ipc_msg);
	ipc_destroy_msg(tmpfs_ipc_struct, ipc_msg);
	if (ret < 0) return 0;
	
	if (--f->refcnt == 0) 
		free(f);
	
	/* LAB 5 TODO END */
	return 0;
}

int double_buf(char* buf, int size) {
	char* new_buf = malloc(sizeof(char) * size);
	memcpy(new_buf, buf, size);
	buf = new_buf;
	size = size * 2;
	return size;
};

/* Need to support %s and %d. */
int fscanf(FILE * f, const char * fmt, ...) {

	/* LAB 5 TODO BEGIN */
	int size = 4096, len = 0, ret;
	char buf[size];

	len = fread(buf, sizeof(char), sizeof(buf), f);

	va_list ap; /* points to each unnamed arg in turn */
	char *fmt_plus_i, *sval, *s_dst, *s_src;
	int* d_dst;
    	int ival;
	int off = 0, copy_dst, copy_len, cal_res;

	va_start(ap,fmt);   /* make ap point to 1st unnamed arg */
	for (int i = 0; ; i++) {
		fmt_plus_i = fmt + i;
		if (!*fmt_plus_i) break;
		if (*fmt_plus_i == '%') {
			fmt_plus_i = fmt_plus_i + 1;
			cal_res = 0;
			if (*fmt_plus_i == 'd') {
				d_dst = va_arg(ap, int *);
				while (off < size && (buf[off] == ' ' || buf[off] == '\n' || buf[off] == '\0')) off++;
				if (buf[off] < '0' || buf[off] > '9') return 0;
				while (off < size && '0' <= buf[off] && buf[off] <= '9') cal_res = (buf[off++] - '0') + cal_res * 10;
				*d_dst = cal_res;
			}
			else if(*fmt_plus_i == 's') {
				s_dst = va_arg(ap, char *);
				while (off < size && (buf[off] == ' ' || buf[off] == '\n' || buf[off] == '\0')) off++;
				copy_dst = off;
				while (copy_dst < size && buf[copy_dst] != ' ' && buf[copy_dst] != '\n' && buf[copy_dst] != '\0') copy_dst++;
				copy_len = copy_dst - off;
				if (copy_len == 0) return 0;
				s_src = malloc(copy_len * sizeof(char));
				memcpy(s_src, buf + off, copy_len);
				off += copy_len;
				strcpy(s_dst, s_src);
			}
			if (*fmt_plus_i == 'd' || *fmt_plus_i == 's') i++;
		}
	}
	va_end(ap);

	/* LAB 5 TODO END */
error:
    return 0;
}

/* Need to support %s and %d. */
int fprintf(FILE * f, const char * fmt, ...) {

	/* LAB 5 TODO BEGIN */
	int size = 4096, len = 0, ival, ival_len = 0;
	char* buf = malloc(sizeof(char) * size);

	va_list ap; /* points to each unnamed arg in turn */
	char *fmt_plus_i, *sval, tmp[64];
	va_start(ap,fmt);   /* make ap point to 1st unnamed arg */

	for (int i = 0; ; i++) {
		fmt_plus_i = fmt + i;
		if (!*fmt_plus_i) break;
		if (*fmt_plus_i == '%') {
			fmt_plus_i = fmt_plus_i + 1;
			if (*fmt_plus_i == 'd') {
				ival = va_arg(ap, int);
				while (ival > 0) { tmp[ival_len++] = (ival % 10) + '0'; ival /= 10; }
				if (strlen(tmp) + ival_len >= size) size = double_buf(buf, size);
				for (int i = ival_len - 1; i >= 0; i--) buf[len++] = tmp[i];
			}
			else if (*fmt_plus_i == 's') {
				for (sval = va_arg(ap, char *); *sval; sval++) {
				if (len >= size)
						size = double_buf(buf, size);
					buf[len++] = *sval;
				}
			}
			if (*fmt_plus_i == 'd' | *fmt_plus_i == 's') i++;
		} else {
			if (len >= size)
				size = double_buf(buf, size);
			buf[len++] = *fmt_plus_i;
		}
	}
	va_end(ap);

	buf[len] = '\0';

	fwrite(buf, sizeof(char), len * sizeof(char), f);
	
	/* LAB 5 TODO END */
    return 0;
};

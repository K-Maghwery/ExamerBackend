package com.online_exam.examer.mapper;


import lombok.Data;
import org.springframework.data.domain.Page;

import java.io.Serializable;
import java.util.List;

@Data
public class PageDto<T>implements Serializable {

    private List<T> content;
    private int pageNumber;
    private int pageSize;
    private long totalElements;
    private int totalPages;

    public PageDto(Page<T> page) {
        this.content = page.getContent();
        this.pageNumber = page.getNumber();
        this.pageSize = page.getSize();
        this.totalElements = page.getTotalElements();
        this.totalPages = page.getTotalPages();
    }

}

package com.utum.mobilegis.domain;

import lombok.Data;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class Results {
    private Boolean success;
    private String msg;
    private Integer ret;
    private List<Object> results;
    private Map<String,Object> data = new HashMap<>();




}

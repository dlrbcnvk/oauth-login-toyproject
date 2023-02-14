package com.tutorial.jsg.oauth.userinfo.impl;

import com.tutorial.jsg.oauth.userinfo.OAuth2UserInfo;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class FacebookUserInfo extends OAuth2UserInfo {

    @Autowired
    private RestTemplate restTemplate;

    public FacebookUserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    /**
     * Facebook에서 imageUrl 불러오려면 따로 api 호출해야 함
     * https://graph.facebook.com/v16.0/{user_id}/picture
     */
    @Override
    public String getImageUrl() {
        String id = getId();
        String url = "https://graph.facebook.com/v16.0/" + id + "/picture?redirect=false";

        ResponseEntity<FacebookUserPhotoDto> response = requestImageUrl(id, url);

        FacebookUserPhotoDto body = response.getBody();
        assert body != null;
        Map<String, Object> data = body.getData();
        Object imageUrl = data.get("url");

        if (imageUrl == null) {
            return null;
        }
        return (String) imageUrl;
    }


    @Getter
    @Setter
    @AllArgsConstructor
    public class FacebookUserPhotoDto {
        private Map<String, Object> data;
        private Map<String, Object> paging;
    }

    private ResponseEntity<FacebookUserPhotoDto> requestImageUrl(String id, String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");
        return restTemplate.getForEntity(url, FacebookUserPhotoDto.class);
    }
}

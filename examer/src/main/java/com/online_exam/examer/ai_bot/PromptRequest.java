package com.online_exam.examer.ai_bot;

import lombok.Data;

@Data
public class PromptRequest {

    private String questionTitle;
    private String questionTopic;
    private int easyQuestion;
    private int mediumQuestion;
    private int hardQuestion;
}

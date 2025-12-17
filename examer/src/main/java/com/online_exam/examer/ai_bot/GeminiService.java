package com.online_exam.examer.ai_bot;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.online_exam.examer.exception.GeminiApiException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class GeminiService {

    @Value("${gemini.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public GeminiService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public List<QuestionDto> generateQuestions(PromptRequest promptRequest) {
        String url = String.format("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=%s", apiKey);

        // Concatenate inputs within a static prompt
        String prompt = "I need "+ (promptRequest.getEasyQuestion()+promptRequest.getMediumQuestion()+promptRequest.getHardQuestion() )+
                " questions split them to "+ promptRequest.getEasyQuestion() + " easy questions, " +
                promptRequest.getMediumQuestion() + " medium questions, and " +
                promptRequest.getHardQuestion() + " hard questions about " +
                promptRequest.getQuestionTopic() + " topics in " + promptRequest.getQuestionTitle() +
                " all questions are MCQ and questionContent not exceed 1000 character," +
                " correct answer, options not exceed 255 character shuffle options to make correct answer not the same option for all questions" +
                "don't add any comments or extra data just questions in form of json make sure to send me the right number of questions" +
                "everytime i send you the same category and topics send me different questions so i need an unique questions everytime" +
                "and map them in form of JSON like this template: {\n" +
                "    \"questionContent\": \"the question description here?\",\n" +
                "    \"difficulty\": \"the level of question difficulty\",\n" +
                "    \"category\": \"set here " + promptRequest.getQuestionTitle() + " for all questions\",\n" +
                "    \"correctAnswer\": \"here is the correct answer\",\n" +
                "    \"option1\": \"answers option1\",\n" +
                "    \"option2\": \"answers option2\",\n" +
                "    \"option3\": \"answers option3\",\n" +
                "    \"option4\": \"answers option4\"\n" +
                "}" ;



        try {
            // Create the payload for Gemini API
            ObjectNode contentNode = objectMapper.createObjectNode();
            ArrayNode partsArray = objectMapper.createArrayNode();
            ObjectNode partsNode = objectMapper.createObjectNode();

            partsNode.put("text", prompt);
            partsArray.add(partsNode);
            contentNode.set("parts", partsArray);

            ObjectNode payload = objectMapper.createObjectNode();
            payload.set("contents", objectMapper.createArrayNode().add(contentNode));

            // Set up the request headers
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/json");

            // Send the POST request
            HttpEntity<String> entity = new HttpEntity<>(payload.toString(), headers);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

            // Parse the response to extract the questions
            JsonNode rootNode = objectMapper.readTree(response.getBody());
            ArrayNode questionsArray = (ArrayNode) rootNode.path("candidates");


            // Extract the "text" field that contains the actual JSON string of questions
            JsonNode textNode = questionsArray.get(0).path("content").path("parts").get(0).path("text");
            String questionJsonString = textNode.asText();


            // Clean the response string by removing backticks, extra formatting, and comments
            questionJsonString = questionJsonString.replace("```json", "").replace("```", "").trim();

// Remove single-line comments (//)
            questionJsonString = questionJsonString.replaceAll("//.*", "");

// Remove multi-line comments (/* ... */)
            questionJsonString = questionJsonString.replaceAll("/\\*.*?\\*/", "");

// Parse the cleaned JSON string into a List of QuestionDto objects



            // Parse the cleaned JSON string into a List of QuestionDto objects
            return objectMapper.readValue(questionJsonString, new TypeReference<List<QuestionDto>>() {});


        } catch (Exception e) {
            throw new GeminiApiException("Error while contacting Gemini API: " + e.getMessage());
        }
    }
}

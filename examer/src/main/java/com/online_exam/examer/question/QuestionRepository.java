package com.online_exam.examer.question;

import com.online_exam.examer.question.dto.CategoryDto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface QuestionRepository extends JpaRepository<QuestionEntity,Long> {
@Query("SELECT new com.online_exam.examer.question.dto.CategoryDto(q.category, " +
        "SUM(CASE WHEN (q.difficulty = 'Easy' OR q.difficulty = 'easy') AND q.isDeleted = false THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN (q.difficulty = 'Medium' OR q.difficulty = 'medium') AND q.isDeleted = false THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN (q.difficulty = 'Hard' OR q.difficulty = 'hard') AND q.isDeleted = false THEN 1 ELSE 0 END), " +
        "COUNT(CASE WHEN q.isDeleted = false THEN 1 ELSE null END)) " +
        "FROM QuestionEntity q " +
        "WHERE q.isDeleted = false " +
        "GROUP BY q.category")
    Page<CategoryDto> findCategoriesWithActiveQuestions(Pageable pageable);

    @Query("SELECT DISTINCT q.category FROM QuestionEntity q WHERE q.isDeleted = false")
    List<String> findDistinctCategoriesWithActiveQuestions();

    List<QuestionEntity> findByCategoryAndIsDeletedFalse(String category);


    // Find all non-deleted questions by category and difficulty
    @Query("SELECT q FROM QuestionEntity q WHERE q.category = :category AND (:difficulty IS NULL OR (q.difficulty = :difficulty OR q.difficulty = LOWER(:difficulty) )) AND q.isDeleted=false")
    Page<QuestionEntity> findByCategory(@Param("category") String category, @Param("difficulty") String difficulty, Pageable pageable);

    @Query("SELECT q FROM QuestionEntity q " +
            "WHERE q.category = :category AND (:difficulty IS NULL OR (q.difficulty = :difficulty OR q.difficulty=LOWER(:difficulty) )) AND q.isDeleted = false")
    Page<QuestionEntity> findByCategoryAndDifficultyAndNotDeleted(
            @Param("category") String category,
            @Param("difficulty") String difficulty,
            Pageable pageable);



    @Query("SELECT q FROM QuestionEntity q JOIN q.exams e WHERE e.examId = :examId")
    List<QuestionEntity> findQuestionsByExamId(@Param("examId") Long examId);

@Query("SELECT new com.online_exam.examer.question.dto.CategoryDto(" +
        "q.category, " +
        "SUM(CASE WHEN (q.difficulty = 'Easy' OR q.difficulty = 'easy') THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN (q.difficulty = 'Medium' OR q.difficulty = 'medium') THEN 1 ELSE 0 END), " +
        "SUM(CASE WHEN (q.difficulty = 'Hard' OR q.difficulty = 'hard') THEN 1 ELSE 0 END), " +
        "COUNT(q)) " +
        "FROM QuestionEntity q " +
        "WHERE q.category = :category AND q.isDeleted = false " +
        "GROUP BY q.category")
CategoryDto findCategoryDetailsByCategoryAndNotDeleted(@Param("category") String category);


    // Check if a question is assigned to any exam
    @Query("SELECT COUNT(e) > 0 FROM QuestionEntity q JOIN q.exams e WHERE q.questionId = :questionId AND q.isDeleted = false")
    boolean existsByIdAndAssignedToAnyExam(@Param("questionId") long questionId);

    Optional<QuestionEntity> findByQuestionIdAndIsDeletedFalse(Long questionId);

    @Query("SELECT q FROM QuestionEntity q WHERE q.category = :category AND (q.difficulty = :difficulty OR q.difficulty=LOWER(:difficulty)) AND q.isDeleted = :deleted")
    Page<QuestionEntity> findByCategoryAndDifficultyAndDeleted(
            @Param("category") String category,
            @Param("difficulty") String difficulty,
            @Param("deleted") boolean deleted,
            Pageable pageable
    );


    Page<QuestionEntity> findByCategoryAndIsDeletedFalse(@Param("category") String category, Pageable pageable);

    /****************** Not Used ******************/

    //Page<QuestionEntity> findAllByIsDeletedFalse(Pageable pageable);

    // Find all non-deleted questions by category and difficulty
    //    @Query("SELECT q FROM QuestionEntity q WHERE q.category = :category AND q.difficulty = :difficulty AND q.isDeleted = false")
    //    Page<QuestionEntity> findByCategoryAndDifficultyAndDeleted(
    //            String category,
    //             String difficulty,
    //              boolean deleted,
    //            Pageable pageable
    //    );

    //Page<CategoryDto> findCategoriesWithActiveQuestions(Pageable pageable);

    //Page<QuestionEntity> findByCategoryAndDifficulty(String category,String difficulty ,Pageable pageable);

    //Page<QuestionEntity> findByCategory(String category, Pageable pageable);

    //Page<CategoryDto> getAvailableCategories(Pageable pageable);

    //@Query("SELECT DISTINCT q.category FROM QuestionEntity q")
    //List<String> findDistinctCategories();

}

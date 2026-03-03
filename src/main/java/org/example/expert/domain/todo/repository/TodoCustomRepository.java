package org.example.expert.domain.todo.repository;

import org.example.expert.domain.todo.dto.response.TodoSearchResponse;
import org.example.expert.domain.todo.entity.Todo;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Optional;

public interface TodoCustomRepository {
    Optional<Todo> findByIdWithUser(Long todoId);
    Page<TodoSearchResponse> findTodos(Pageable pageable, String title, String nickname, LocalDateTime startDate, LocalDateTime endDate);
}

package org.example.expert.domain.todo.repository;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import org.example.expert.domain.comment.entity.QComment;
import org.example.expert.domain.manager.entity.QManager;
import org.example.expert.domain.todo.dto.response.TodoSearchResponse;
import org.example.expert.domain.todo.entity.QTodo;
import org.example.expert.domain.todo.entity.Todo;
import org.example.expert.domain.user.entity.QUser;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class TodoCustomRepositoryImpl implements TodoCustomRepository {

    private final JPAQueryFactory jpaQueryFactory;

    private final QTodo todo = QTodo.todo;
    private final QUser user = QUser.user;
    private final QManager manager = QManager.manager;
    private final QComment comment = QComment.comment;

    @Override
    public Optional<Todo> findByIdWithUser(Long todoId) {
        return Optional.ofNullable(jpaQueryFactory
                .selectFrom(todo)
                .leftJoin(user).on(user.id.eq(todo.userId))
                .where(todo.id.eq(todoId))
                .fetchOne());
    }

    @Override
    public Page<TodoSearchResponse> findTodos(Pageable pageable, String title, String nickname, LocalDateTime startDate, LocalDateTime endDate) {
        BooleanBuilder builder = new BooleanBuilder();

        if (title != null && !title.isEmpty()) {
            builder.and(todo.title.contains(title));
        }

        if (nickname != null && !nickname.isEmpty()) {
            builder.and(user.nickname.contains(nickname));
        }

        if (startDate != null) {
            builder.and(todo.createdAt.goe(startDate));
        }

        if (endDate != null) {
            builder.and(todo.createdAt.lt(endDate));
        }

        List<TodoSearchResponse> results = jpaQueryFactory
                .select(Projections.constructor(TodoSearchResponse.class,
                        todo.title,
                        manager.count(),
                        comment.count()
                ))
                .from(todo)
                .leftJoin(manager).on(manager.todo.id.eq(todo.id))
                .leftJoin(user).on(user.id.eq(manager.userId))
                .leftJoin(comment).on(comment.todo.id.eq(todo.id))
                .where(builder)
                .groupBy(todo.id)
                .orderBy(todo.createdAt.desc())
                .offset(pageable.getOffset())
                .limit(pageable.getPageSize())
                .fetch();

        Long total = jpaQueryFactory
                .select(todo.countDistinct())
                .from(todo)
                .leftJoin(manager).on(manager.todo.id.eq(todo.id))
                .leftJoin(user).on(user.id.eq(manager.userId))
                .where(builder)
                .fetchOne();

        return new PageImpl<>(results, pageable, total == null ? 0 : total);
    }

}

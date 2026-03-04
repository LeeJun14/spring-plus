package org.example.expert.domain.log.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.example.expert.domain.common.entity.Timestamped;

import java.time.LocalDateTime;

@Getter
@Entity
@Table(name = "Logs")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Log extends Timestamped {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;

    private Long toDoId;

    private String groupId;

    private LocalDateTime dateTime;

    @Builder
    public Log(Long userId, Long toDoId, String groupId) {
        this.userId = userId;
        this.toDoId = toDoId;
        this.groupId = groupId;
    }

}

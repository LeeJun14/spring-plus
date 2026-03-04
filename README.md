# SPRING PLUS

---

## Level 1

---

### 1. 코드 개선 - `@Transactional` 의 이해

#### 문제 원인

`TodoService` 클래스 레벨에 `@Transactional(readOnly = true)` 가 선언되어 있어, 쓰기 작업이 필요한 `saveTodo()` 메서드까지 읽기 전용 트랜잭션으로 실행되었습니다.

```
could not execute statement [Connection is read-only. Queries leading to data modification are not allowed]
```

#### 해결 방법

클래스 레벨의 `@Transactional(readOnly = true)` 를 제거하고, 각 메서드에 적합한 트랜잭션 옵션을 개별 적용했습니다.

- 쓰기 작업 (`saveTodo`) → `@Transactional`
- 읽기 작업 (`getTodos`, `getTodo`) → `@Transactional(readOnly = true)`

```java
@Service
@RequiredArgsConstructor
public class TodoService {

    private final TodoRepository todoRepository;
    private final WeatherClient weatherClient;

    @Transactional
    public TodoSaveResponse saveTodo(AuthUser authUser, TodoSaveRequest todoSaveRequest) {
        User user = User.fromAuthUser(authUser);
        String weather = weatherClient.getTodayWeather();

        Todo newTodo = new Todo(
                todoSaveRequest.getTitle(),
                todoSaveRequest.getContents(),
                weather,
                user
        );
        Todo savedTodo = todoRepository.save(newTodo);

        return new TodoSaveResponse(
                savedTodo.getId(),
                savedTodo.getTitle(),
                savedTodo.getContents(),
                weather,
                new UserResponse(user.getId(), user.getEmail())
        );
    }
}
```

---

### 2. 코드 추가 - JWT의 이해

#### 요구 사항

- `User` 테이블에 `nickname` 컬럼 추가 
- 프론트엔드에서 JWT를 파싱해 닉네임을 화면에 표시할 수 있도록 JWT claim에 `nickname` 포함

#### 변경 흐름

회원가입 요청 → `nickname` DB 저장 → JWT claim에 포함 → 필터에서 추출 → `AuthUser` 객체에 주입

#### 수정 파일 목록

| 파일 | 변경 내용 |
|------|-----------|
| `User` | `nickname` 컬럼 추가 및 생성자 수정 |
| `AuthUser` | `nickname` 필드 추가 |
| `SignupRequest` | 요청 Body에 `nickname` 필드 추가 |
| `JwtUtil` | `createToken()` 에 `nickname` claim 추가 |
| `JwtFilter` | JWT에서 `nickname` 추출 후 request attribute 설정 |
| `AuthUserArgumentResolver` | request attribute에서 `nickname` 읽어 `AuthUser` 생성 |

#### 주요 코드

**`User.java`**
```java
@Entity
@Table(name = "users")
public class User extends Timestamped {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true)
    private String email;
    private String password;
    private String nickname;  // 추가
    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    public User(String email, String password, String nickname, UserRole userRole) {
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.userRole = userRole;
    }
}
```

**`JwtUtil.java`** — `nickname` claim 추가
```java
public String createToken(Long userId, String email, String nickname, UserRole userRole) {
    Date date = new Date();
    return BEARER_PREFIX +
            Jwts.builder()
                    .setSubject(String.valueOf(userId))
                    .claim("email", email)
                    .claim("nickname", nickname)  // 추가
                    .claim("userRole", userRole)
                    .setExpiration(new Date(date.getTime() + TOKEN_TIME))
                    .setIssuedAt(date)
                    .signWith(key, signatureAlgorithm)
                    .compact();
}
```

**`JwtFilter.java`** — `nickname` attribute 설정
```java
httpRequest.setAttribute("userId", Long.parseLong(claims.getSubject()));
httpRequest.setAttribute("email", claims.get("email"));
httpRequest.setAttribute("nickname", claims.get("nickname"));  // 추가
httpRequest.setAttribute("userRole", claims.get("userRole"));
```

**`AuthUserArgumentResolver.java`** — `nickname` 주입
```java
Long userId = (Long) request.getAttribute("userId");
String email = (String) request.getAttribute("email");
String nickname = (String) request.getAttribute("nickname");  // 추가
UserRole userRole = UserRole.of((String) request.getAttribute("userRole"));

return new AuthUser(userId, email, nickname, userRole);
```

---

### 3. 코드 개선 - JPA의 이해

#### 요구 사항

- 할 일 목록 조회 시 `weather` 조건으로 필터링 (선택적)
- 수정일 (`modifiedAt`) 기준 기간 검색 기능 추가 (시작일, 종료일 모두 선택적)
- JPQL 사용

#### 해결 방법

JPQL에서 `:param IS NULL OR ...` 패턴을 활용해, 파라미터가 `null` 이면 해당 조건을 무시하도록 구현했습니다. 이를 통해 단일 쿼리로 모든 경우를 처리합니다.

**`TodoRepository.java`**
```java
@Query("SELECT t FROM Todo t LEFT JOIN FETCH t.user u " +
        "WHERE (:weather IS NULL OR t.weather = :weather) " +
        "AND (:startDate IS NULL OR t.modifiedAt >= :startDate) " +
        "AND (:endDate IS NULL OR t.modifiedAt <= :endDate) " +
        "ORDER BY t.modifiedAt DESC")
Page<Todo> findByWeatherAndModifiedAtBetween(
        Pageable pageable,
        @Param("weather") String weather,
        @Param("startDate") LocalDateTime startDate,
        @Param("endDate") LocalDateTime endDate
);
```

**`TodoController.java`** — 쿼리 파라미터 추가
```java
@GetMapping("/todos")
public ResponseEntity<Page<TodoResponse>> getTodos(
        @RequestParam(defaultValue = "1") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(required = false) String weather,
        @RequestParam(required = false) LocalDateTime startDate,
        @RequestParam(required = false) LocalDateTime endDate
) {
    return ResponseEntity.ok(todoService.getTodos(page, size, weather, startDate, endDate));
}
```

---

### 4. 테스트 코드 수정 - 컨트롤러 테스트의 이해

#### 문제 원인

`todo_단건_조회_시_todo가_존재하지_않아_예외가_발생한다()` 테스트에서 기대 상태값이 `200 OK` 로 작성되어 있었으나, 실제로는 `InvalidRequestException` 발생 시 `400 Bad Request` 를 반환합니다.

#### 해결 방법

기대 상태값 및 응답 Body 검증 조건을 `400 Bad Request` 기준으로 수정했습니다.

```java
@Test
void todo_단건_조회_시_todo가_존재하지_않아_예외가_발생한다() throws Exception {
    // given
    long todoId = 1L;

    // when
    when(todoService.getTodo(todoId))
            .thenThrow(new InvalidRequestException("Todo not found"));

    // then
    mockMvc.perform(get("/todos/{todoId}", todoId))
            .andExpect(status().isBadRequest())                                    // 200 → 400 수정
            .andExpect(jsonPath("$.status").value(HttpStatus.BAD_REQUEST.name()))
            .andExpect(jsonPath("$.code").value(HttpStatus.BAD_REQUEST.value()))
            .andExpect(jsonPath("$.message").value("Todo not found"));
}
```

---

### 5. 코드 개선 - AOP의 이해

#### 문제 원인

`AdminAccessLoggingAspect` 에 두 가지 오류가 있었습니다.

1. `@After` 로 선언되어 메서드 실행 **후** 동작 → `@Before` 로 변경 필요
2. Pointcut 대상이 `UserController.getUser()` 로 잘못 지정되어 있었음 → `UserAdminController.changeUserRole()` 로 수정 필요

#### 해결 방법

```java
// 수정 전
@After("execution(* org.example.expert.domain.user.controller.UserController.getUser(..))")

// 수정 후
@Before("execution(* org.example.expert.domain.user.controller.UserAdminController.changeUserRole(..))")
```

**`AdminAccessLoggingAspect.java`**
```java
@Slf4j
@Aspect
@Component
@RequiredArgsConstructor
public class AdminAccessLoggingAspect {

    private final HttpServletRequest request;

    @Before("execution(* org.example.expert.domain.user.controller.UserAdminController.changeUserRole(..))")
    public void logBeforeChangeUserRole(JoinPoint joinPoint) {
        String userId = String.valueOf(request.getAttribute("userId"));
        String requestUrl = request.getRequestURI();
        LocalDateTime requestTime = LocalDateTime.now();

        log.info("Admin Access Log - User ID: {}, Request Time: {}, Request URL: {}, Method: {}",
                userId, requestTime, requestUrl, joinPoint.getSignature().getName());
    }
}
```
---

### 6. JPA Cascade

#### 요구 사항

할 일을 새로 저장할 때, 할 일을 생성한 유저가 담당자(`Manager`)로 자동 등록되어야 합니다.

#### 해결 방법

`Todo` 엔티티의 `managers` 연관관계에 `CascadeType.PERSIST` 를 추가하였습니다.

**`Todo.java`**
```java
@OneToMany(mappedBy = "todo", cascade = CascadeType.PERSIST)
private List managers = new ArrayList<>();
```

`todoRepository.save(todo)` 호출 시 `CascadeType.PERSIST` 에 의해 `managers` 리스트 내의 `Manager` 도 함께 INSERT됩니다. 

---

### 7. N+1

#### 문제 원인

`CommentRepository` 의 기존 쿼리가 `JOIN` 만 사용하고 있어, 각 `Comment` 에 대해 연관된 `User` 를 별도로 조회하는 N+1 문제가 발생하고 있었습니다.

```java
// 기존 — N+1 발생
@Query("SELECT c FROM Comment c JOIN c.user WHERE c.todo.id = :todoId")
```

Comment 1건을 조회할 때마다 `user` 를 가져오기 위한 추가 쿼리가 N번 실행되는 구조입니다.

#### 해결 방법

`JOIN` 을 `LEFT JOIN FETCH` 로 변경해 Comment와 User를 한 번의 쿼리로 함께 조회하도록 수정했습니다.

**`CommentRepository.java`**
```java
// 수정 후 — 단일 쿼리로 해결
@Query("SELECT c FROM Comment c LEFT JOIN FETCH c.user WHERE c.todo.id = :todoId")
List findByTodoIdWithUser(@Param("todoId") Long todoId);
```

`LEFT JOIN FETCH` 를 사용하면 Comment와 연관된 User 데이터를 한 번의 JOIN 쿼리로 가져오므로 추가 쿼리가 발생하지 않습니다.

---

### 8. QueryDSL

#### 요구 사항

`TodoService.getTodo()` 에서 사용하던 JPQL 기반의 `findByIdWithUser` 를 QueryDSL로 변경하고, N+1 문제가 발생하지 않도록 구현합니다.

#### 구현 방법

Custom Repository 패턴을 사용해 QueryDSL 구현체를 분리했습니다.

**수정 파일 목록**

| 파일 | 역할 |
|------|------|
| `QuerydslConfig` | `JPAQueryFactory` 빈 등록 |
| `TodoCustomRepository` | 커스텀 메서드 인터페이스 정의 |
| `TodoCustomRepositoryImpl` | QueryDSL 구현체 |
| `TodoRepository` | `TodoCustomRepository` 상속 추가 및 기존 JPQL 메서드 제거 |

**`QuerydslConfig.java`**
```java
@Configuration
public class QuerydslConfig {
    @PersistenceContext
    private EntityManager em;

    @Bean
    public JPAQueryFactory jpaQueryFactory() {
        return new JPAQueryFactory(em);
    }
}
```

**`TodoCustomRepository.java`**
```java
public interface TodoCustomRepository {
    Optional findByIdWithUser(Long todoId);
}
```

**`TodoCustomRepositoryImpl.java`** — `leftJoin().fetchJoin()` 으로 N+1 방지
```java
@RequiredArgsConstructor
public class TodoCustomRepositoryImpl implements TodoCustomRepository {
    private final JPAQueryFactory jpaQueryFactory;

    @Override
    public Optional findByIdWithUser(Long todoId) {
        QTodo todo = QTodo.todo;
        QUser user = QUser.user;

        return Optional.ofNullable(jpaQueryFactory
                .selectFrom(todo)
                .leftJoin(todo.user, user).fetchJoin()
                .where(todo.id.eq(todoId))
                .fetchOne());
    }
}
```

**`TodoRepository.java`** — 커스텀 레포지토리 상속 및 기존 JPQL 메서드 제거
```java
public interface TodoRepository extends JpaRepository, TodoCustomRepository {
    // findByIdWithUser 는 TodoCustomRepositoryImpl 에서 QueryDSL로 처리
}
```

---

### 9. Spring Security

#### 요구 사항

기존의 `Filter` + `ArgumentResolver` 기반 인증 방식을 Spring Security로 전환합니다. JWT 토큰 기반 인증 방식은 유지하고, 접근 권한 및 유저 권한 기능은 Spring Security의 기능을 활용합니다.

#### 변경 흐름

기존: `JwtFilter(Filter)` → request attribute 저장 → `AuthUserArgumentResolver` 에서 `AuthUser` 생성

변경: `JwtFilter(OncePerRequestFilter)` → `SecurityContextHolder` 에 인증 정보 저장 → `@AuthenticationPrincipal` 로 `AuthUser` 주입

#### 수정 파일 목록

| 파일 | 변경 내용 |
|------|-----------|
| `AuthUser` | `UserDetails` 구현 추가 |
| `JwtFilter` | `Filter` → `OncePerRequestFilter` 로 변경, `SecurityContextHolder` 에 인증 정보 저장 |
| `SecurityConfig` | `SecurityFilterChain` 빈 등록, 경로별 권한 설정 |

**`AuthUser.java`** — `UserDetails` 구현
```java
public class AuthUser implements UserDetails {
    private final Long id;
    private final String email;
    private final String nickname;
    private final UserRole userRole;

    @Override
    public Collection getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + userRole.name()));
    }

    @Override
    public String getUsername() { return email; }

    @Override
    public String getPassword() { return null; }

    // isAccountNonExpired, isAccountNonLocked, isCredentialsNonExpired, isEnabled → 모두 true 반환
}
```

**`JwtFilter.java`** — `OncePerRequestFilter` 로 변경 및 SecurityContext 저장
```java
public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        String bearerJwt = request.getHeader("Authorization");
        if (bearerJwt == null) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String token = jwtUtil.substringToken(bearerJwt);
            Claims claims = jwtUtil.extractClaims(token);

            Long userId = Long.parseLong(claims.getSubject());
            String email = claims.get("email", String.class);
            String nickname = claims.get("nickname", String.class);
            UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));

            AuthUser authUser = new AuthUser(userId, email, nickname, userRole);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(authUser, null, authUser.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);

        } catch (ExpiredJwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token expired");
        } catch (JwtException e) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "token invalid");
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error");
        }
    }
}
```

**`SecurityConfig.java`** — 경로별 접근 권한 설정
```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
        );
        http.addFilterBefore(new JwtFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

---

### 10. QueryDSL을 사용하여 검색 기능 만들기

#### 요구 사항

- 새로운 API (`GET /todos/search`) 로 일정 검색 기능 구현
- 검색 조건: 제목 키워드(부분 일치), 담당자 닉네임(부분 일치), 생성일 범위
- 반환값: 제목, 담당자 수, 총 댓글 수 (페이징 처리)
- `Projections` 를 활용해 필요한 필드만 반환

#### 구현 방법

`BooleanBuilder` 로 조건을 동적으로 조합하고, `Projections.constructor` 로 `TodoSearchResponse` DTO에 필요한 필드만 매핑했습니다. 담당자 수와 댓글 수는 `manager.count()`, `comment.count()` 로 집계하고 `groupBy(todo.id)` 로 일정 단위로 묶었습니다.

**`TodoSearchResponse.java`** — 필요한 필드만 담는 DTO
```java
@Getter
@RequiredArgsConstructor
public class TodoSearchResponse {
    private final String title;
    private final long managerCount;
    private final long commentCount;
}
```

**`TodoCustomRepositoryImpl.java`** — QueryDSL 검색 구현
```java
@Override
public Page findTodos(Pageable pageable, String title, String nickname,
                                          LocalDateTime startDate, LocalDateTime endDate) {
    BooleanBuilder builder = new BooleanBuilder();

    if (title != null && !title.isEmpty()) {
        builder.and(todo.title.contains(title));         // 제목 부분 일치
    }
    if (nickname != null && !nickname.isEmpty()) {
        builder.and(user.nickname.contains(nickname));   // 닉네임 부분 일치
    }
    if (startDate != null) {
        builder.and(todo.createdAt.goe(startDate));      // 생성일 시작 범위
    }
    if (endDate != null) {
        builder.and(todo.createdAt.lt(endDate));         // 생성일 종료 범위
    }

    List results = jpaQueryFactory
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
```

`Projections.constructor` 를 사용하면 엔티티 전체를 조회하지 않고 필요한 컬럼만 SELECT하기 때문에 불필요한 데이터 전송을 줄일 수 있습니다. `total` 카운트 쿼리는 페이징 처리를 위해 별도로 실행합니다.

**`TodoController.java`** — 검색 API 추가
```java
@GetMapping("/todos/search")
public ResponseEntity<Page> getTodosSearch(
        @RequestParam(defaultValue = "1") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(required = false) String title,
        @RequestParam(required = false) String nickname,
        @RequestParam(required = false) LocalDateTime startDate,
        @RequestParam(required = false) LocalDateTime endDate
) {
    return ResponseEntity.ok(todoService.getTodosSearch(page, size, title, nickname, startDate, endDate));
}
```

---

### 11. Transaction 심화

#### 요구 사항

- 매니저 등록 요청 시 로그 테이블(`log`)에 항상 요청 로그를 남깁니다.
- 매니저 등록이 실패하더라도 로그는 반드시 저장되어야 합니다.

#### 핵심 아이디어

매니저 등록과 로그 저장이 같은 트랜잭션에 묶이면, 매니저 등록 실패 시 로그도 함께 롤백됩니다. 이를 방지하기 위해 `Propagation.REQUIRES_NEW` 를 사용해 로그 저장을 **독립된 별도 트랜잭션**으로 분리했습니다.

```
매니저 등록 트랜잭션 (실패 가능)
└── 로그 저장 트랜잭션 (REQUIRES_NEW — 항상 커밋)
```

**`Log.java`** — 로그 엔티티
```java
@Entity
@Table(name = "Logs")
public class Log extends Timestamped {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Long userId;   // 요청한 유저 ID
    private Long toDoId;   // 대상 일정 ID
    private String groupId; // 요청 식별용 UUID
    private LocalDateTime dateTime;

    @Builder
    public Log(Long userId, Long toDoId, String groupId) {
        this.userId = userId;
        this.toDoId = toDoId;
        this.groupId = groupId;
    }
}
```

**`LogService.java`** — `REQUIRES_NEW` 로 독립 트랜잭션 처리
```java
@Service
@RequiredArgsConstructor
public class LogService {
    private final LogRepository logRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void saveRequestHistory(User user, Todo todo, String groupId) {
        Log log = Log.builder()
                .userId(user.getId())
                .toDoId(todo.getId())
                .groupId(groupId)
                .build();
        logRepository.save(log);
    }
}
```

**`ManagerService.java`** — 매니저 등록 전 로그 저장 호출
```java
@Transactional
public ManagerSaveResponse saveManager(AuthUser authUser, long todoId, ManagerSaveRequest managerSaveRequest) {
    // ... 유효성 검사 ...

    String groupId = "rfnd-grp-" + UUID.randomUUID();
    logService.saveRequestHistory(user, todo, groupId);  // 별도 트랜잭션으로 실행

    Manager newManagerUser = new Manager(managerUser.getId(), todo);
    Manager savedManagerUser = managerRepository.save(newManagerUser);
    // ...
}
```

`REQUIRES_NEW` 는 기존 트랜잭션을 일시 중단하고 새로운 트랜잭션을 시작합니다. 로그 저장이 완료되면 즉시 커밋되므로, 이후 매니저 등록 로직이 예외로 롤백되더라도 로그 레코드는 DB에 남아있게 됩니다.
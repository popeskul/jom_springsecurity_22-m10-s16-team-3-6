package com.softserve.itacademy.controller;

import com.softserve.itacademy.exception.CustomAccessDeniedException;
import com.softserve.itacademy.model.Task;
import com.softserve.itacademy.model.ToDo;
import com.softserve.itacademy.model.User;
import com.softserve.itacademy.security.PersonDetails;
import com.softserve.itacademy.service.TaskService;
import com.softserve.itacademy.service.ToDoService;
import com.softserve.itacademy.service.UserService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/todos")
public class ToDoController {

    private final ToDoService todoService;
    private final TaskService taskService;
    private final UserService userService;

    public ToDoController(ToDoService todoService, TaskService taskService, UserService userService) {
        this.todoService = todoService;
        this.taskService = taskService;
        this.userService = userService;
    }

    @GetMapping("/create/users/{owner_id}")
    @PreAuthorize("isAuthenticated()")
    public String create(@PathVariable("owner_id") long ownerId, Model model) {
        model.addAttribute("todo", new ToDo());
        model.addAttribute("ownerId", ownerId);
        return "create-todo";
    }

    @PostMapping("/create/users/{owner_id}")
    @PreAuthorize("isAuthenticated()")
    public String create(@PathVariable("owner_id") long ownerId, @Validated @ModelAttribute("todo") ToDo todo, BindingResult result) {
        if (result.hasErrors()) {
            return "create-todo";
        }
        todo.setCreatedAt(LocalDateTime.now());
        todo.setOwner(userService.readById(ownerId));
        todoService.create(todo);
        return "redirect:/todos/all/users/" + ownerId;
    }

    @GetMapping("/{id}/tasks")
    @PreAuthorize("isAuthenticated()")
    public String read(@PathVariable long id, Model model) throws CustomAccessDeniedException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        PersonDetails authedUser = (PersonDetails) authentication.getPrincipal();

        ToDo todo = todoService.readById(id);
        if (todo.getCollaborators().stream().noneMatch(user -> user.getId() == authedUser.getId()) && todo.getOwner().getId() != authedUser.getId()) {
            throw new CustomAccessDeniedException();
        }

        List<Task> tasks = taskService.getByTodoId(id);
        List<User> users = userService.getAll().stream()
                .filter(user -> user.getId() != todo.getOwner().getId()).collect(Collectors.toList());
        model.addAttribute("todo", todo);
        model.addAttribute("tasks", tasks);
        model.addAttribute("users", users);
        return "todo-tasks";
    }

    @GetMapping("/{todo_id}/update/users/{owner_id}")
    @PreAuthorize("hasAuthority('ADMIN') or @toDoServiceImpl.readById(#todoId).owner.id == authentication.principal.id")
    public String update(@PathVariable("todo_id") long todoId, @PathVariable("owner_id") long ownerId, Model model) {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        PersonDetails authedUser = (PersonDetails) authentication.getPrincipal();

        ToDo todo = todoService.readById(todoId);
//        if (todo.getOwner().getId() != authedUser.getId()) {
//            throw new CustomAccessDeniedException();
//        }

        model.addAttribute("todo", todo);
        return "update-todo";
    }

    @PostMapping("/{todo_id}/update/users/{owner_id}")
    @PreAuthorize("hasAuthority('ADMIN') or @toDoServiceImpl.readById(#todoId).owner.id == authentication.principal.id")
    public String update(@PathVariable("todo_id") long todoId, @PathVariable("owner_id") long ownerId,
                         @Validated @ModelAttribute("todo") ToDo todo, BindingResult result) {
        if (result.hasErrors()) {
            todo.setOwner(userService.readById(ownerId));
            return "update-todo";
        }

//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        PersonDetails authedUser = (PersonDetails) authentication.getPrincipal();

        ToDo oldTodo = todoService.readById(todoId);
//        if (todo.getOwner().getId() == authedUser.getId()) {
//            throw new CustomAccessDeniedException();
//        }

        todo.setOwner(oldTodo.getOwner());
        todo.setCollaborators(oldTodo.getCollaborators());
        todoService.update(todo);
        return "redirect:/todos/all/users/" + ownerId;
    }

    @GetMapping("/{todo_id}/delete/users/{owner_id}")
    @PreAuthorize("hasAuthority('ADMIN') or @toDoServiceImpl.readById(#todoId).owner.id == authentication.principal.id")
    public String delete(@PathVariable("todo_id") long todoId, @PathVariable("owner_id") long ownerId) {
        todoService.delete(todoId);
        return "redirect:/todos/all/users/" + ownerId;
    }

    @GetMapping("/all/users/{user_id}")
    @PreAuthorize("hasAuthority('ADMIN') or #userId == authentication.principal.id")
    public String getAll(@PathVariable("user_id") long userId, Model model) {
        List<ToDo> todos = todoService.getByUserId(userId);
        model.addAttribute("todos", todos);
        model.addAttribute("user", userService.readById(userId));
        return "todos-user";
    }

    @GetMapping("/{id}/add")
    @PreAuthorize("hasAuthority('ADMIN') or @toDoServiceImpl.readById(#id).owner.id == authentication.principal.id")
    public String addCollaborator(@PathVariable long id, @RequestParam("user_id") long userId) {
        ToDo todo = todoService.readById(id);
        List<User> collaborators = todo.getCollaborators();
        collaborators.add(userService.readById(userId));
        todo.setCollaborators(collaborators);
        todoService.update(todo);
        return "redirect:/todos/" + id + "/tasks";
    }

    @GetMapping("/{id}/remove")
    @PreAuthorize("hasAuthority('ADMIN') or @toDoServiceImpl.readById(#id).owner.id == authentication.principal.id")
    public String removeCollaborator(@PathVariable long id, @RequestParam("user_id") long userId) {
        ToDo todo = todoService.readById(id);
        List<User> collaborators = todo.getCollaborators();
        collaborators.remove(userService.readById(userId));
        todo.setCollaborators(collaborators);
        todoService.update(todo);
        return "redirect:/todos/" + id + "/tasks";
    }
}

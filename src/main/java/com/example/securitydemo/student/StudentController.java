package com.example.securitydemo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1L, "James Bond"),
            new Student(2L, "Maria Jones"),
            new Student(3L, "Anna Smith"));


    @GetMapping("/{studentId}")
    public Student getStudent(@PathVariable Long studentId) {
        return STUDENTS.stream().filter(s -> s.getStudentId() == studentId)
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Student with id " + studentId + " does not exist."));
    }
}

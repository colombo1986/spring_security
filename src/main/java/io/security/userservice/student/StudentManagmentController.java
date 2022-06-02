package io.security.userservice.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("managment/api/v1/students")

public class StudentManagmentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2,"Maria Jones"),
            new Student(3, "Ana Smith")
    );
//hasRole(ROLE_) hasAnyRole(ROLE_) , hasAuthority('permission') hasAuthority('permission')
    @GetMapping

    public List<Student> getAllStudents(){
        System.out.println("getAllStudents");
        return STUDENTS ;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("registerNewStudent");
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN , ROLE_ADMINTRAINEE')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){

        System.out.println("deleteStudent");
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN , ROLE_ADMINTRAINEE')")
    public void updateStudent(@PathVariable("studentId")Integer studentId,@RequestBody Student student){
        System.out.println("updateStudent");
        System.out.println(String.format("%s %s", studentId, student));
    }
}

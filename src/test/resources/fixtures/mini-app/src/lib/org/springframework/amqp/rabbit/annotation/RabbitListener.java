package org.springframework.amqp.rabbit.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Stub of the Spring AMQP API, for compiling the app fixtures (A6). */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RabbitListener {

    String[] value() default {};
}

package es.milfist;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class practicas {

    Example example1 = new Example("Mik");
    Example example2 = new Example("Mik1");
    Example example3 = new Example("Mik2");
    Example example4 = new Example("Mik3");








    @Test
    public void streamTest() {

        List<Example> list = new ArrayList<>();
        list.add(example1);
        list.add(example2);
        list.add(example3);
        list.add(example4);

//		List<String> ctos = new ArrayList<>();
//		for (Resource resource : resources) {
//			ctos.add(resource.getName());
//		}
        List<String> l = list.stream().map(Example::getName).collect(Collectors.toList());



    }




}


class Example {
    private String name;

    public Example(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
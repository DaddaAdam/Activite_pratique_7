package ma.emsi.customerfrontthymeleafapp.web;

import lombok.AllArgsConstructor;
import ma.emsi.customerfrontthymeleafapp.entities.Customer;
import ma.emsi.customerfrontthymeleafapp.repository.CustomerRepository;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.List;

@Controller
@AllArgsConstructor
public class CustomerController {
    private CustomerRepository customerRepository;

    @GetMapping("/customers")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String customers(Model model){
        List<Customer> customerList = customerRepository.findAll();
        model.addAttribute("customers", customerList);
        return "customers";
    }

    @GetMapping("/products")
    public String products(Model model){

        return "products";
    }

    @GetMapping("/auth")
    @ResponseBody
    public Authentication auth(Authentication authentication){
        return authentication;
    }

    @GetMapping("/")
    public String index(){
        return "index";
    }
}

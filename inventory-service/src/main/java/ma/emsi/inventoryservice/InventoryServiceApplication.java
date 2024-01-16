package ma.emsi.inventoryservice;

import ma.emsi.inventoryservice.entities.Product;
import ma.emsi.inventoryservice.repository.ProductRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.UUID;

@SpringBootApplication
public class InventoryServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(InventoryServiceApplication.class, args);
	}

	@Bean
	CommandLineRunner start(ProductRepository productRepository) {
		return args -> {
			productRepository.save(new Product(UUID.randomUUID().toString(), "Computer", 788, 12));
			productRepository.save(new Product(UUID.randomUUID().toString(), "Printer", 788, 12));
			productRepository.save(new Product(UUID.randomUUID().toString(), "Phone", 788, 12));
			productRepository.findAll().forEach(System.out::println);
		};
	}

}

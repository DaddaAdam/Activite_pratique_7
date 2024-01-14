package ma.emsi.customerfrontthymeleafapp.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.*;

@Entity
@NoArgsConstructor @AllArgsConstructor @Getter @Setter @ToString @Builder
public class Customer {
    @Id @GeneratedValue(strategy = jakarta.persistence.GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String email;
}

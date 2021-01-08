package cert.config;

import com.webank.cert.service.CertService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author wesleywang
 */
@Configuration
public class CertBeans {

    @Bean
    public CertService getCertService(){
        return new CertService();
    }


}

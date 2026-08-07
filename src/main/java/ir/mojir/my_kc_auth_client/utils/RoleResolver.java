package ir.mojir.my_kc_auth_client.utils;

import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import ir.mojir.my_kc_auth_client.annotations.AllowedRoles;
import ir.mojir.spring_boot_commons.exceptions.InternalErrorException;

@Component("myRoleResolver")
public class RoleResolver {
    private final RequestMappingHandlerMapping handlerMapping;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ApplicationContext applicationContext;

    public RoleResolver(@Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping handlerMapping,
    		ApplicationContext applicationContext) {
        this.handlerMapping = handlerMapping;
        this.applicationContext = applicationContext;
    }

    public String[] getAllowedRoles(String httpMethod, String path) {
        RequestMethod requestMethod = RequestMethod.valueOf(httpMethod.toUpperCase());

        for (Map.Entry<RequestMappingInfo, HandlerMethod> entry :
                handlerMapping.getHandlerMethods().entrySet()) {

            RequestMappingInfo info = entry.getKey();
            HandlerMethod handlerMethod = entry.getValue();

            // --- Get patterns safely ---
            Set<String> patterns = new HashSet<>();

            if (info.getPathPatternsCondition() != null) {
                info.getPathPatternsCondition().getPatterns()
                        .forEach(p -> patterns.add(p.getPatternString()));
            } else if (info.getPatternsCondition() != null) {
                patterns.addAll(info.getPatternsCondition().getPatterns());
            }

            // --- Match method ---
            if (info.getMethodsCondition().getMethods().contains(requestMethod)) {
                // --- Match path ---
                for (String pattern : patterns) {
                    if (pathMatcher.match(pattern, path)) {
                        AllowedRoles annotation = handlerMethod.getMethodAnnotation(AllowedRoles.class);
                        if (annotation != null) {
                        	if (!annotation.rolesProvider().isBlank()) {
                        		try {
                        			Object bean = handlerMethod.getBean();

                        			if (bean instanceof String beanName) {
                        			    bean = applicationContext.getBean(beanName);
                        			}

                        			Method provider = bean.getClass()
                        			        .getMethod(annotation.rolesProvider());

                        			return (String[]) provider.invoke(bean);
                        		} catch (Exception e) {
                        			throw new InternalErrorException("Failed to get allowed roles from child class.", e);
                        		}
                        	} else {
                        	    return annotation.roles();
                        	}
                        }
                    }
                }
            }
        }

        return new String[0];
    }
    
//    private Object getBean() {
//    	
//    }
}

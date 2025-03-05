package ir.mojir.my_kc_auth_client.exceptions;

import org.springframework.http.HttpStatus;

import ir.mojir.spring_boot_commons.dtos.ErrorDto;
import ir.mojir.spring_boot_commons.enums.ErrorEnum;
import ir.mojir.spring_boot_commons.exceptions.ServiceException;

@SuppressWarnings("serial")
public class KeycloakAuthorizationClientException extends ServiceException{

	public KeycloakAuthorizationClientException(String message, Throwable e) {
		super(new ErrorDto(message, ErrorEnum.INTERNAL_ERROR), e);
	}

	@Override
	public HttpStatus getHttpStatus() {
		return HttpStatus.INTERNAL_SERVER_ERROR;
	}

}

import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class UpdateUserDto {
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsString()
  username: string;
}

export class UpdateUserPasswordDto {
  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  confirm_password: string;
}

import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class AuthUserDto {
  @IsNotEmpty()
  @IsString()
  email_or_username: string;

  @IsNotEmpty()
  @IsString()
  @MinLength(6)
  password: string;
}

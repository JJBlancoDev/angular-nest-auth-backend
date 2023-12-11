import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-User.dto';

export class UpdateAuthDto extends PartialType(CreateUserDto) {}

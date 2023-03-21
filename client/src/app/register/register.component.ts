import { Component, EventEmitter, Input, OnInit, Output } from '@angular/core';
import { ToastrService } from 'ngx-toastr';
import { AccountService } from '../_services/account.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
  @Output() cancleRegister = new EventEmitter(); 
  model: any={}

  constructor (private accountService : AccountService, private toastr: ToastrService) {}
  
  
  ngOnInit(): void {}
  

  register() {
    this.accountService.register(this.model).subscribe({
      next:()=>{
        this.cancle();
      },
      error: error => 
      {
        this.toastr.error(error.error),
        console.log(error)
      }
    })
  }
  cancle() {
    this.cancleRegister.emit(false);
  }
}
